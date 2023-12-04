# schema

All schema's placed in here are nDPId exclusive, meaning that they are not necessarily representing a "real-world" JSON message received by e.g. `./example/py-json-stdout`.
This is due to the fact that libnDPI itself add's some JSON information to the serializer of which we have no control over.
IMHO it makes no sense to include stuff here that is part of libnDPI.
