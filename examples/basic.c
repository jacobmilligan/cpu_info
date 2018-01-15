//
//  basic.c
//  cpu_info
//
//  --------------------------------------------------------------
//
//  Created by
//  Jacob Milligan on 15/01/2018
//  Copyright (c) 2016 Jacob Milligan. All rights reserved.
//

#define CPU_INFO_IMPLEMENTATION

#include <cpu_info.h>

#include <stdio.h>
#include <stdlib.h>


int main(int argc, char** argv)
{
    cpui_result result;
    int info_err = cpui_get_info(&result);
    if (info_err) {
        fprintf(stderr, "An error occured when trying to get cpu info: error code: %s\n",
                cpui_error_strings[info_err]);
        exit(EXIT_FAILURE);
    }

    printf("Physical cores: %d. Logical cores: %d\n", result.physical_cores,
           result.logical_cores);
}