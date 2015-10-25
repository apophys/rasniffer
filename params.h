/**
 * params.h
 * Author: Milan Kubík, xkubik17@stud.fit.vutbr.cz
 * Date: October 2010
 *
 */
#ifndef __PARAMS_H
#define __PARAMS_H

#include <stdbool.h>

struct params_t {
  char *interface;
  bool emit;
  bool solicit;
};

int parse_params(int argc, char *argv[], struct params_t *params);
#endif
