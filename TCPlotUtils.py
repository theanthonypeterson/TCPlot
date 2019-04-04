#!/usr/bin/env python2

import socket

def parseBoolean(o):
   s = str(o)
   if s.lower() == "false":
      return False
   if s == "":
      return False
   if s == "0":
      return False
   return True


# GIVEN: a collection of real values
# WHERE: len(l) > 0
# RETURNS: the average of the given list of values
def avg(l):
    return sum(l) / (len(l) * 1.0)

	
# GIVEN: a collection of real values
# RETURNS: the standard deviation of the given list of values
def stddev(l):
    m = avg(l)
    return avg(list(map(lambda x: (x-m)**2, l)))**0.5

	
# GIVEN: a collection of real values
# RETURNS: the median of the given list of values
def med(l):
    n = len(l)
    i = (n-1)//2
    s = sorted(l)
    if n % 2 == 0:
        return (s[i] + s[i+1])/2.0
    return s[i]
	

# GIVEN: a collection of real values
# RETURNS: the minimum, greater than zero, value of the given collection
def minGreaterThan0(l):
    currentMin = -1
    for v in l:
        if currentMin == -1 or (v > 0 and v < currentMin):
            currentMin = v
    return currentMin
	
	
# GIVEN: an ip address
# RETURNS: ip address in dotted notation
def inet_to_str(inet):
   try:
      return socket.inet_ntop(socket.AF_INET, inet)
   except ValueError:
      return socket.inet_ntop(socket.AF_INET6, inet)
