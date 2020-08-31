%module openpgp_bridge
%{
#include "openpgp_bridge.h"
%}

%include <typemaps.i>
%include "std_string.i"
%include "std_vector.i"

namespace std {
}

%include "openpgp_bridge.h"
