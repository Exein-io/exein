# Exein

Exein framework's goal is to accomplish the task of protecting the target system from undesirable behavior, introducing the self-protecting and remote-monitoring set of tools into the embedded systems arena.

![splash](/docs/imgs/splash.jpg)

The natural position of a piece of software providing **Run-time anomaly detection** features is within the Linux kernel using the Linux Security Module ecosystem.

The task of analyzing the system behavior enumerating system's event is divided into three macro functions:

- Collecting event at OS level (**LSM Exein**)
- Providing a mean of communication between kernel space  section and the userspace applications (**Exein_interface**)
- Analyzing them using machine learning algorithms (**MLEPlayer**)

The **LSM Exein** is the part of the Exein solution which interfaces with the Linux kernel and exports the system events data to the userspace application module for the analysis. Its main functions are:

- Interfacing with the Linux Kernel
- Collecting the events flows
- Enforcing policies dictated by the *MLEPlayer*

The **Exein_interface** is the glue that makes it possible for the userspace MLEPlayer to communicate with the *LSM Exein*. It accomplishes this task by defining a new protocol within the Linux Netlink stack. It also provides userspace tools for debugging purposes.

The next part of the list is the code part where the actual computation is performed by the machine learning algorithms.  The code block element is called **MLEPlayer**.

The **MLEPlayer** embodies the following functions:

- Receives data from the *Exein_interface*
- Sends policies to the *Exein_interface*
- Triggers the machine learning algorithm on the supplied data


![design](/docs/imgs/exein.png)


## User space
- libexnl: the library implements the NetLink agent in charge for collecting data, registers the application to the kernel and keeps this registration active. It also provides functions for fetching data and pushing policies.
- MLEPlayer: Using Tensorflow 2.0.0 it performs the actual computation, tracking the target application behavior.


## Kernel
- LSM: this module is embedded within the Linux Kernel image, it collects data from applications and exports them to the requiring MLEPlayers.
- LKM: This Linux Kernel Module provides Netlink interface to the MLEPlayer, and some useful tools for debugging the solution.
- patch/exec/task_struct: In order for the solution to work, a few patches to the original Linux Kernel are required. To be more specific, for a process to be tracked it needs to be easily recognized among others. The patch allows an executable tagged in its ELF header to bring this tag to its task struct, and therefore to be recognized among the others.



## Getting started
Once this repo have been downloaded, in order to build Exein you may want to follow the next steps:

 1. Build Exein enabled kernel
 2. Build the libexnl
 3. Build the mle-player
 4. Tag your target executable
 5. Train a model for your target process
 6. Test the solution


### Dependencies
In order to build the Exein you need an environment which includes the following dependencies:
 - tensorflow lite 2.0 or above
 - xtensor 0.20 or above
 - Linux 4.14.162

### Build Exein enabled kernel
Follow these steps:

 - Download the **kernel 4.14.162** (https://cdn.kernel.org/pub/linux/kernel/v4.x/linux-4.14.162.tar.gz)
 - Copy the provided repository kernel directory contents in the original kernel 4.14.162 directory. Alternatively you can use the kernel patch included in this repository to the original kernel 4.14.162 directory.
 - run **make menuconfig** to enable the Exein module options; in the "**security options**" section and in the "**Device Drivers**" section.
Now the Linux Kernel is ready to be used with the Exein MLE-Player.

### Build the libexnl
To build **libexnl** is a quite straight forward process. Simply go to the main lib directory and run `make`; then place the *./lib/libexnl.so* files in your project lib directory.

### Build the mle-player
To build **mle-player** is a quite straight forward process. Simply go to the main app directory and run `make`; then place the *mle-player* files in its final destination.

### Tag your target executable
To tag an executable is as easy as adding a section in your elf executable file.
Here's an example:
```
echo -ne "\x33\x33" > exein
objcopy --add-section .exein=exein --set-section-flags .exein=noload,readonly /usr/sbin/uhttpd
rm exein

```
NOTE: you need to use your native architecture *objcopy*, or the cross tool for your target architecture.


### Train a model for your target process
The training of a model starts with the extraction of the target process behavioral data. To collect data from a tagged running process, enable kernel training mode and use `/utils/training-forwarder` included in this repository. To enable kernel training mode, just write something in `/proc/exein/mode_ctl`.

Just compile the `training-forwarder` for your target architecture and run it specifying the monitored process tag and the udp destination where the training-receiver server is listening.

For example to forward training data for tag 13107 to the server listening at UDP:192.168.1.10:13107 using kernel seed 35465436  use the following:
```
echo 1 > /proc/exein/mode_ctl
./training-forwarder 192.168.1.10 13107 13107 35465436 1350
```
and then use the training-receiver application. The objective of this activity is to collect the regular behavioral data, therefore it is suggested to test all the functionalities you expect to be used in the target application.
The *training receiver* tool will produce a fairly large csv containing the application regular behavior.
At the time of this writing, the online service for training models is not online yet. If you need to train a new model feel free to send the csv file produced by the *training receiver* tool to **test \<at\> exein.io** and we'll send you back the trained model.  


### Test the solution
MLE-Player is acting as client with respect to the kernel service. In order to receive processes data it needs to register itself to the kernel. For security reasons, each time the kernel is compiled it will generate a random seed, which will be used by the client to prove it is authorized to communicate with the kernel. This seed needs to be specified in the MLE-Player command-line. ROOT users can retrieve this information using the following:  
```
# dmesg |grep "ExeinLSM - lsm is active"
[    0.001962] ExeinLSM - lsm is active: seed [1841749789]
```

to start an instance of the MLE-Player you may use the following syntax
```
# mle-player 1841749789 ARMEL-F-414162-config-13107.ini ARMEL-F-414162-model-13107.tflite
```
where the first argument is the *security kernel seed*, the second is the path of the *model config file*, and the third is the *tflite model*.

This repository comes with a few models targeted to `uhttpd` as example. You can find them in the `/sample-models` directory.

Here's an example where the monitored process is the **uhttpd**.  

![test-example](/docs/imgs/test-example.gif)  

During the test you should observe that regular traffic to the server is allowed, whereas the non regular behavior of an HTTP server instance acting as a shell is detected and terminated.  

Looking at the MLE-Player output, you should see something like the following:

```
Starting Exein monitoring for tag: 13107
libexnl staring up
Now checking pid 835
INFO: Initialized TensorFlow Lite runtime.
Now checking pid 4432
Now checking pid 4438
Removing pid 4432
Now checking pid 4463
Removing pid 4463
Now checking pid 4481
Block process: 4438
Removing pid 4438
Removing pid 4481
```

Here's a brief description of the most meaningful parts:  

- The first line __Starting Exein monitoring for tag: 13107__ indicates that the MLE-Player instance is watching at the tag 13107, the tag assigned to the HTTP server.  

Tags are a central concept of the Exein framework. They act as classifiers and let the Exein framework identify the target processes and their children.
Tags are basically 16-bits identifiers that are embedded into executables by adding a section within the ELF header and are checked every time the executable is ran.

- As traffic to the server starts, one by one, the HTTP server processes are added to the watch-list.

__Now checking pid 835__ notifies the process 835 was added to the watch-list.

- As soon as anomalies are detected, the MLE-Player reacts asking the LSM to take action against the abnormal process (see __Block process: 4438__ message).


## Tested devices
- Qemu arm32
- Qemu mips malta
- Raspberry PI BCM2709 (Raspberry PI 3+ in arm32 mode)
- Ramips MT7688
- Olinuxino i.MX233 ARM926J
- STM32MP157C-DK2
