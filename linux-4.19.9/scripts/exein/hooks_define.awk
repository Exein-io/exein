BEGIN {
       config="NONE";
      }
{
 if ($1== "#ifdef") config=$2; 
               else if ($1== "#endif") config="NONE"; 
                                  else {
                                        str=sprintf( (config=="NONE")?"#define EXEIN_%2$s_SWITCH":"#ifdef %s\n#define EXEIN_%s_SWITCH\n#endif",config, toupper($0));
                                        print str;
                                       }
 }
