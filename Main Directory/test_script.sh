rm -rf test_dir
mkdir test_dir
touch test_dir/a.txt
mkdir test_dir/b
touch test_dir/b/c.tsa
cd test_programs
rm -rf *.virus
for i in *.c
do
        `gcc -g3 -o3 $i -o ${i%.c}`
done
for i in *.cpp
do
        `g++ $i -o ${i%.cpp}`
done
cd ..

