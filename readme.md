This experimental profiler written in Python2  measures file i/o operations inside Python applications before flushing data from buffers to a disk and displays data flows using Graphviz diagrams.

The profiler uses BFS (Breadth-First Search) algorithm to visualize the shortest paths from an entry application function to read and written files.

Run a recorder and pytest unit tests to record log events: python2 ./rw_ops_log_recorder.py -l ~/log.txt

Run a compressor to reduce i/o events: python2 ./rw_ops_log_compressor.py -i ~/log.txt -o ~/clog.txt

Run an analyzer to visualize data flows: python2 ./rw_ops_log_analyzer.py -l ~/clog.txt -r ~/report -o svg

(Graphviz)[https://en.wikipedia.org/wiki/Graphviz]
