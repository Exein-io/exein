/* Copyright 2019 Exein. All Rights Reserved.

Licensed under the GNU General Public License, Version 3.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.gnu.org/licenses/gpl-3.0.html

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
==============================================================================*/

#include <cmath>
#include <cstdio>
#include <cstdlib>

#include <algorithm>
#include <iostream>
#include <string>
#include <vector>

#include <tensorflow/lite/interpreter.h>
#include <tensorflow/lite/kernels/register.h>
#include <tensorflow/lite/model.h>
#include <tensorflow/lite/optional_debug_tools.h>

#include <xtensor/xarray.hpp>
#include <xtensor/xio.hpp>
#include <xtensor/xadapt.hpp>

#include "INIReader.h"
extern "C" {
#include <libexnl.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/resource.h>
#include <execinfo.h>
}

#define COLOR 0
//#define DEBUG
#ifdef DEBUG
#define DODEBUG( ... ) printf( __VA_ARGS__ ); fflush(stdout);
#else
#define DODEBUG( ... ) do { } while(0)
#endif

#define STATE_INIT_START                0
#define STATE_INIT_SIGNAL               1
#define STATE_INIT_TENSOR               2
#define STATE_WORKER_START_ITERATION    3
#define STATE_WORKER_GOING_TO_DIE       4
#define STATE_WORKER_DATA_FETCHED       5
#define STATE_WORKER_DATA_PREPARED      6
#define STATE_WORKER_DATA_GREENLIGHT    7
#define STATE_WORKER_DATA_COMPUTED      8
#define STATE_WORKER_PROCESS_KILL       9
#define STATE_MASTER_IDLE               10
#define STATE_MASTER_BREEDING           11
#define STATE_MLE_PLAYER_INIT           12
#define STATE_MLE_PLAYER_ZEROS_CNTD     13
#define STATE_MLE_PLAYER_HOOKS_SHAPED   14
#define STATE_MLE_PLAYER_ONE_SHOT       15
#define STATE_MLE_PLAYER_PREDICTED      16
#define STATE_MLE_PLAYER_ERROR_CALC     17
#define STATE_MLE_PLAYER_ERROR_DONE     18


using namespace tflite;

//#define EXEIN_DEBUG
#define PID_STORE_SIZE 1024

#define TFLITE_MINIMAL_CHECK(x)                                  \
    if (!(x)) {                                                  \
        fprintf(stderr, "Error at %s:%d\n", __FILE__, __LINE__); \
        exit(1);                                                 \
    }

#define LOG(x) std::cerr
uint16_t data[EXEIN_BUFFES_SIZE];
typedef struct {
    int16_t index;
    pid_t pids[PID_STORE_SIZE];
} pidqueue;

typedef struct {
    int16_t size;
    pid_t pids[PID_STORE_SIZE];
} rnd_access_arr;


pidqueue				addpid;
rnd_access_arr				*terminate;
std::map<int, xt::xarray<float>>	predictions;
std::map<int, xt::xarray<float>>	errors;
std::map<int, xt::xarray<int>>		old_hooks;
uint16_t				pidl4 = 0;
pid_t					tmppid, tmppid2;
volatile sig_atomic_t			sigchld_f=0;
exein_shandle				*h;
int					sample_index, cnt;
int					__attribute__((used)) state;


static void stack_tr() {
    void *trace[EXEIN_BACKTRACE_SIZE];
    char **messages = (char **)NULL;
    int i, trace_size = 0;

    trace_size = backtrace(trace, EXEIN_BACKTRACE_SIZE);
    messages = backtrace_symbols(trace, trace_size);
    printf("[stack trace(%d) ]>>>\n", trace_size);
    for (i=0; i < trace_size; i++)
        printf("%s\n", messages[i]);
    printf("<<<[stack trace]\n");
    free(messages);
}


void sigsegv_handler(int sig, siginfo_t *si, void *unused) {
    switch (sig) {
        case SIGSEGV:
            printf("sigsegv_handler - pid %d got SIGSEGV at address: 0x%lx\n", getpid(), (long) si->si_addr);
            stack_tr();
            signal(sig, SIG_DFL);
            kill(getpid(), sig);
            exit(-1);
        case SIGCHLD:
            DODEBUG("sigchld_handler - pid %d got SIGCHLD from %d\n", getpid(), si->si_pid);
            sigchld_f++;
            break;
        default:
            printf("sigsegv_handler -[%d] Reecived Signal :%d\n",getpid(), sig);
    };
}


pid_t dequeue(pidqueue *q, int remove){
    if (q->index>-1) {
        DODEBUG("dequeue: index=%d return=%d\n", q->index, q->pids[q->index]);
        return q->pids[remove==0?q->index:q->index--];
    } else return 0;
}


void inqueue(pidqueue *q, pid_t p){
    DODEBUG("inqueue: index=%d val=%d\n", q->index, p);
    if (q->index<PID_STORE_SIZE) q->pids[++q->index]=p;
}

int is_in(pid_t p, rnd_access_arr *pid_repo){
        int index=0, found=0;
        while((index<PID_STORE_SIZE)&&(found<pid_repo->size)&&(pid_repo->pids[index]!=p)) {
                if (pid_repo->pids[index]!=0) found++;
                index++;
                }
        if(pid_repo->pids[index]==p){
                pid_repo->pids[index]=0;
                pid_repo->size--;
                return 1;
                }
        return 0;
}

void put_in(pid_t p, rnd_access_arr *pid_repo){
        int index=0;
        while((index<PID_STORE_SIZE)&&(pid_repo->pids[index]!=0)) index++;
        if (index<PID_STORE_SIZE) pid_repo->pids[index]=p;
        pid_repo->size++;
}


// Utility functions

std::vector<int> split(std::string str) {
    std::stringstream ss(str);
    std::string s;
    std::vector<int> hooks;

    while (getline(ss, s, ',')) {
        hooks.push_back(std::stoi(s));
    }

    return hooks;
}


xt::xarray<int> isin(int hid, std::vector<int> item, int val, int notval) {

    xt::xarray<int>::shape_type sh0 = {1, item.size()};
    auto res = xt::empty<int>(sh0);
    res.fill(notval);
    for (size_t i = 0; i < item.size(); i++) {
        if (hid == item[i]) {
            res(i) = val;
            break;
        }
    }

  return res;
}


xt::xarray<int> isnotin(xt::xarray<int> arr, std::vector<int> item, int val) {
    xt::xarray<int>::shape_type sh0 = arr.shape();
    auto res = xt::empty<int>(sh0);
    res.fill(val);
    for (auto i: item) {
        xt::xarray<int>::iterator iter = arr.begin();
        while ((iter = std::find(iter, arr.end(), i)) != arr.end()) {
            int dis = std::distance(arr.begin(), iter);
            res(dis) = arr(dis);
            iter++;
        }
    }

    return res;
}



// TF player functions

xt::xarray<float> make_prediction(tflite::Interpreter* interpreter, xt::xarray<int> x, std::vector<int> output_shape) {
    // use tflite interpreter to perform inference
    auto input_array = xt::cast<float>(xt::expand_dims(x ,0));
    float* input = interpreter->typed_input_tensor<float>(0);

#ifdef EXEIN_DEBUG
    printf("Value stored in a variable input is: %f\n",*input);
#endif

    std::copy(input_array.begin(), input_array.end(), input);
    TFLITE_MINIMAL_CHECK(interpreter->Invoke() == kTfLiteOk);
    float* output_f = interpreter->typed_output_tensor<float>(0);

#ifdef EXEIN_DEBUG
    printf("Value stored in a variable output is: %f\n",*output_f);
#endif

    std::vector<float> output_v {output_f, output_f + output_shape[1]};
    xt::xarray<float> output = xt::adapt(output_v, output_shape);

    return output;
}


std::vector<int> get_tensor_shape(TfLiteTensor* tensor) {
    std::vector<int> shape;
    const int dims = tensor->dims->size;

    for (int i = 0; i < dims; ++i) {
        shape.push_back(tensor->dims->data[i]);
    }

    return shape;
}


xt::xarray<int> one_hot(xt::xarray<int> arr, std::vector<int> hooks, int ws) {
    // encode array of hooks as one-hot vector
    xt::xarray<int>::shape_type sh0 = {hooks.size(), arr.size()};
    auto res = xt::empty<int>(sh0);
    for (int h = 0; h < hooks.size(); h++) {
        for (int a = 0; a < arr.size(); a++) {
            res(a+h*ws) = (arr(a)==hooks[h]);
        }
    }

    return xt::transpose(res);
}


float cross_entropy(xt::xarray<float> predictions, xt::xarray<int> targets) {
    // compute cross entropy between latest prediction and actual observation (anomaly score)
    const double epsilon = std::pow(10, -12);

    predictions = xt::clip(predictions, epsilon, 1. - epsilon);
    auto xent = xt::sum(targets * xt::log(predictions), /*axis*/1);

    return -xent(0);
}


xt::xarray<float> update_error(xt::xarray<float> old_err_arr, float new_err) {
    // update prediction error array for current pid
    std::rotate(old_err_arr.begin(), old_err_arr.begin()+1, old_err_arr.end());
    old_err_arr(old_err_arr.size() - 1) = new_err;

    return old_err_arr;
}


/*
Load and initialize tflite interpreter and other tag-specific meta-parameters
:param models_dir: directory where .tflite and .ini saved files are stored
:param tag: tag we are interested in
:return: dictionary containing model and parameters for the tag
*/
std::map<string, string> initialize_exein(const char* config_file) {
    INIReader reader(config_file);
    std::map<string, string> model_params;

    model_params["window_size"] = reader.Get("PARAMS", "window_size", "15");
    model_params["rolling_size"] = reader.Get("PARAMS", "rolling_size", "60");
    model_params["tag"] = reader.Get("PARAMS", "tag", "-1");
    model_params["threshold"] = reader.Get("PARAMS", "threshold", "2.0");
    model_params["hooks"] = reader.Get("PARAMS", "hooks", "UNKNOWN");

    return model_params;
}


/*
Logic for the tag-specific MLE player.
:param hook_arr: array storing the last N hooks for the given PID
:param pid: pid that we want to investigate
:param tag_metaparms: dictionary containing all the necessary info for the tag (hooks, model, window_size, threshold and rolling_size)
:param: predictions: dictionary storing the last prediction for each PID (needed for checking signal)
:return:
*/
std::tuple<std::map<int, xt::xarray<float>>, std::map<int, xt::xarray<float>>, int>
mle_player(tflite::Interpreter* interpreter, xt::xarray<int> hook_arr, uint16_t pid,
           std::map<string, string> model_params, std::map<int, xt::xarray<float>> predictions,
           std::map<int, xt::xarray<float>> errors) {

    state=STATE_MLE_PLAYER_INIT;
    xt::xarray<float> pred;
    DODEBUG("mle_player - begin \n");
    // get meta-parameters from dictionary
    std::vector<int> hooks = split(model_params["hooks"]);
    int window_size = std::stoi(model_params["window_size"]);
    float threshold = std::stof(model_params["threshold"]);
    int rolling_size = std::stoi(model_params["rolling_size"]);
    int i;

   cnt=0;
   // evaluate zeros at the beginnig
   for (i=0; i< hook_arr.size(); i++ ){
       if (hook_arr(i)==COLOR) cnt++;
          else break;
          }
    state=STATE_MLE_PLAYER_ZEROS_CNTD;
    sample_index=rand()%(  hook_arr.size() - window_size - 1 - cnt);
    std::vector<int> wsize_hook_arr_tmp(hook_arr.begin()+sample_index+cnt, hook_arr.begin()+sample_index+window_size+cnt);
    std::vector<std::size_t> shape = { 1, window_size };
    auto wsize_hook_arr = xt::adapt(wsize_hook_arr_tmp, shape);

    state=STATE_MLE_PLAYER_HOOKS_SHAPED;
#ifdef EXEIN_DEBUG
    std::cout << wsize_hook_arr << "\n";
#endif

    xt::xarray<int> x_tmp = isnotin(wsize_hook_arr, hooks, -1);
    xt::xarray<int> x = one_hot(x_tmp, hooks, window_size);

    state=STATE_MLE_PLAYER_ONE_SHOT;
    int output = interpreter->outputs()[0];
    std::vector<int> output_shape = get_tensor_shape(interpreter->tensor(output));

    // make prediction and update prediction dict
    pred = make_prediction(interpreter, x, output_shape);

    state=STATE_MLE_PLAYER_PREDICTED;
    predictions[pid] = pred;

    // check for signal
    int signal = 0;
    if (xt::mean(predictions[pid])() != 0) {
        xt::xarray<int> onehot_hid;
        int hid = hook_arr[sample_index + cnt + window_size];

        // turn latest Hook ID into one-hot vecto
        if (std::find(hooks.begin(), hooks.end(), hid) != hooks.end())
            onehot_hid = isin(hid, hooks, 1, 0);
        else
            onehot_hid = isin(-1, hooks, 1, 0);
        state=STATE_MLE_PLAYER_ERROR_CALC;
        float err = cross_entropy(predictions[pid], onehot_hid);
        state=STATE_MLE_PLAYER_ERROR_DONE;

        if (xt::mean(errors[pid])() != 0) {
            errors[pid] = update_error(errors[pid], err);
        } else {
            xt::xarray<float> errors_p = xt::zeros<float>({1, rolling_size});
            errors[pid] = update_error(errors_p, err);
        }

        // compute moving average over the last rolling_size errors for the PID
        float m_avg_err = xt::mean(errors[pid])();
#ifdef EXEIN_DEBUG
        std::cout << "AVG: " << m_avg_err << "\n";
#endif

        // compare with threshold to check for an attack signal
        signal = (m_avg_err > threshold)? 1 : 0;
    }

    return std::make_tuple(predictions, errors, signal);
}


void new_pid_notify_cb(uint16_t pid) { //TODO: fork COW
    inqueue(&addpid, (pid_t) pid);
    printf("Now checking pid %d\n", pid);
    exein_add_pid(h, pid);
}

void removed_pid_notify_cb(uint16_t pid) {
    put_in((pid_t) pid, terminate);
    printf("Removing pid %d\n", pid);
}


/*
Run the exein mle on historical data for the tag specified (simulate online execution).
:param data: dataset (numpy array) containing Hook IDs, PIDs and Tag
:param model_params: .tflite model and other meta parameters
:param tag: tag we are interested in
:return: Nothing, run the exein mle model
*/
int main(int argc, char* argv[]) {
    if (argc != 4) {
        fprintf(stderr, "mle-player <secret> <config file> <tflite model> \n");
        return 1;
    }

    int				secret = std::stoi(argv[1]);
    const char			*config_file = argv[2];
    const char			*model_name = argv[3];
    std::map<string, string>	model_params;
    int				signal_ = 0;
    struct sigaction		sa = {0};
    exein_pids *		pid_data=NULL;

    state=STATE_INIT_START;
    srand(time(NULL));

    terminate = (rnd_access_arr *)  mmap(NULL, sizeof(rnd_access_arr), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0); //probably it takes 4k, as a linux memory page is defined.
    memset(terminate, 0, sizeof(rnd_access_arr)); //size field is set to 0  by memset

    addpid.index=-1;
    model_params = initialize_exein(config_file);
    int tag = std::stoi(model_params["tag"]);

    std::cout << "Starting Exein monitoring for tag: " << tag << '\n';

    exein_new_pid_notify_cb = &new_pid_notify_cb;
    exein_delete_pid_cb = &removed_pid_notify_cb;

    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        printf("Receive feeds can't install the signal handler.");
    }

signal(SIGCHLD, SIG_IGN);

    if (!(h = exein_agent_start(secret, tag))) {
        std::cout << "Can't starting Exein agent" << '\n';
        return 1;
    }

    state=STATE_INIT_SIGNAL;
    DODEBUG("model init\n");
    std::unique_ptr<tflite::FlatBufferModel> model = tflite::FlatBufferModel::BuildFromFile(model_name);
    TFLITE_MINIMAL_CHECK(model != nullptr);

    // Build the interpreter
    tflite::ops::builtin::BuiltinOpResolver resolver;
    InterpreterBuilder builder(*model, resolver);
    std::unique_ptr<Interpreter> interpreter;
    builder(&interpreter);
    TFLITE_MINIMAL_CHECK(interpreter != nullptr);
    DODEBUG("Model stuffs done\ninit tensors\n");
    // Allocate tensor buffers.
    TFLITE_MINIMAL_CHECK(interpreter->AllocateTensors() == kTfLiteOk);
    DODEBUG("Tensors done\n");
    state=STATE_INIT_TENSOR;
    while (true) { //pid specialized processes
        //DODEBUG("MainLoop Itaration pid=%d\n", pidl4);
        if((pidl4!= 0)) {
            state=STATE_WORKER_START_ITERATION;
            DODEBUG("[T%d-M%d] iteration started| ", pidl4, getpid());
            if (is_in(pidl4,terminate)) {
                state=STATE_WORKER_GOING_TO_DIE;
		if (pid_data) {
			exein_remove_pid(h,(uint16_t) pidl4);
			pid_data=NULL;
			}
                DODEBUG("[T%d-M%d] have been named. RIP\n", pidl4, getpid());
                exit(pidl4);
            }
            DODEBUG("[T%d-M%d] is fetching data| ", pidl4, getpid());
            // here 
            if (!pid_data) pid_data=exein_find_data(h, pidl4);
            if ((pid_data)&&(exein_fetch_data(h, pidl4, data, pid_data) == EXEIN_NOERR)) {
                state=STATE_WORKER_DATA_FETCHED;
                std::vector<std::size_t> shape = { EXEIN_BUFFES_SIZE };
                auto input_data = xt::adapt((short unsigned int*)data, EXEIN_BUFFES_SIZE, xt::no_ownership(), shape);
                state=STATE_WORKER_DATA_PREPARED;
                if (old_hooks.count(pidl4) == 0) {
                    old_hooks[pidl4] = input_data;
                } else {
                    if (old_hooks[pidl4] == input_data) {
                        continue;
                    } else {
                        old_hooks[pidl4] = input_data;
                    }
                }

                int nonzero = EXEIN_BUFFES_SIZE - std::count(input_data.begin(), input_data.end(), COLOR);
                if (nonzero < std::stoi(model_params["window_size"])+5) {
                    continue;
                }
                state=STATE_WORKER_DATA_GREENLIGHT;
#ifdef DEBUG
                std::cout << "--------------------------------" << "\n";
                std::cout << pidl4 << " input data: " << input_data << '\n';
                std::cout << "prediction for: " << pidl4 << std::endl;
#endif

                std::tie(predictions, errors, signal_) = mle_player(interpreter.get(), input_data, pidl4, model_params, predictions, errors);

                for (auto e: errors) {
                    std::cout << e.first << ": " << e.second << "\n";
                }

                state=STATE_WORKER_DATA_COMPUTED;
                if (signal_) {
                    state=STATE_WORKER_PROCESS_KILL;
                    std::cout << "Block process: " << pidl4 << "\n";
                    for (auto e: errors) {
                        std::cout << e.first << ": " << e.second << "\n";
                        }
                    std::cout << pidl4 << " input data: " << input_data << '\n';
                    std::cout << sample_index << '\n';
                    std::cout << cnt << '\n';
                    std::vector<int> wsize_hook_arr_tmp(input_data.begin()+sample_index+cnt, input_data.begin()+sample_index+10+cnt);
                    std::vector<std::size_t> shape = { 1, 10 };
                    auto wsize_hook_arr = xt::adapt(wsize_hook_arr_tmp, shape);

                    std::cout << wsize_hook_arr << '\n';
                    exein_block_process(h, pidl4, secret, tag);
                }
            } else {
                DODEBUG("[T%d-M%d] fetch_data timeout\n", pidl4, getpid() );
	    }
        } else {// Master process
            state=STATE_MASTER_IDLE;
            usleep(300);
            state=STATE_MASTER_BREEDING;
	    if (sigchld_f>0) {
		wait(NULL);
		sigchld_f--;
		}
            if ((tmppid=dequeue(&addpid,1))!=0) {
                if ((tmppid2=fork())==0) {
                    pidl4=tmppid;
                } else {
                    printf("\nNew pid appeared = [T%d-M%d] \n", tmppid, tmppid2);
                }
            }
        }
    }

    exein_agent_stop(h);
    return 0;
}

