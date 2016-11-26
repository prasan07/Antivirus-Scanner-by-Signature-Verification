rm -rf test_dir
mkdir test_dir
touch test_dir/a.txt
mkdir test_dir/b
touch test_dir/b/c.tsa
cd test_programs
rm -rf hello.virus
rm -rf cpp_virus.virus
gcc hello.c -o hello
g++ cpp_virus.cpp -o cpp_virus
cd ..

