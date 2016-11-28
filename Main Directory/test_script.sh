cd test_programs
cd c_progs
rm -rf *.virus
for i in *.c
do
        `gcc -g3 -o3 $i -o ${i%.c}`
done
cd ../
cd c++_progs
rm -rf *.virus
for i in *.cpp
do
        `g++ $i -o ${i%.cpp}`
done
cd ../..

