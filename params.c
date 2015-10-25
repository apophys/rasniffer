/**
 * params.c
 * Author: Milan Kubík, xkubik17@stud.fit.vutbr.cz
 * Date: October 2010
 *
 * Description:
 *   parse command line input
 */

#include <assert.h>
#include <stdlib.h>
#include <stdbool.h>
#include <getopt.h>

#include "params.h"

/*
 * Takes argc, argv and parses command line input
 */
int parse_params(int argc, char* argv[], struct params_t *params)
{
  assert(params);

  params->interface = NULL;
  params->emit = false;
  params->solicit = false;

  int c;
  const char *optargs = "i:rs";

  while ((c = getopt(argc, argv, optargs)) != -1) {
    switch (c) {
      case 'i':
  params->interface = optarg;
  break;

      case 'r':
  params->emit = true;
  break;

      case 's':
  params->solicit = true;
  break;

      case '?':
      default:
  return EXIT_FAILURE;
  break;
    }
  }
  if (params->interface == NULL)
   return EXIT_FAILURE;

  return EXIT_SUCCESS;
}

