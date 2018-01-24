#!/bin/sh

export TEST_AREA=${HOME}/test_area

#Setup preparation
rm -rf $TEST_AREA
mkdir -p $TEST_AREA
echo XXRRRRX > ${TEST_AREA}/filerp
mkdir -p ${TEST_AREA}/dirrp
echo aaaaa > ${TEST_AREA}/dirrp/file
echo kkkkk > ${TEST_AREA}/dirrp/file1
echo kkkkk > ${TEST_AREA}/dirrp/file2
echo XXRRRRX > ${TEST_AREA}/filerp1
mkdir -p ${TEST_AREA}/dirwp
echo kkkkk > ${TEST_AREA}/dirwp/file1
echo XXXXXXX > ${TEST_AREA}/filewp
echo ls > ${TEST_AREA}/filexp
chmod +x ${TEST_AREA}/filexp

#echo ls > ${TEST_AREA}/filexp
#chmod +x ${TEST_AREA}/filexp
#echo ls > ${TEST_AREA}/filexpm1
#chmod +x ${TEST_AREA}/filexpm1
#echo ls > ${TEST_AREA}/filexpm2
#chmod +x ${TEST_AREA}/filexpm2
#echo kkkkk > ${TEST_AREA}/dirwp/file1
#echo kkkkk > ${TEST_AREA}/dirwp/file2
#mkdir -p ${TEST_AREA}/dirxp
#echo ls > ${TEST_AREA}/dirxp/file1
#chmod +x ${TEST_AREA}/dirxp/file1
#mkdir -p ${TEST_AREA}/dirwp1

err_count=0
test_count=0

echo "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% Read protected tests %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"

echo "***************** Ls a read protected directory"
python create_rule.py -a drop -t file -n 1 -f ${TEST_AREA}/dirrp -p 4 > json_tmp_file
./build/bin/sr_test -f json_tmp_file
test_count=$((test_count+1))
ls ${TEST_AREA}/dirrp > /dev/null
status=$?
echo "expect DENIED -status: ${status}"
if [ $status -eq 0 ]; then
   echo "Error test${test_count}"
   err_count=$((err_count+1))
fi

echo "***************** Read a read protected file"
python create_rule.py -a drop -t file -n 1 -f ${TEST_AREA}/filerp -p 4 > json_tmp_file
./build/bin/sr_test -f json_tmp_file
test_count=$((test_count+1))
cat ${TEST_AREA}/filerp > /dev/null
status=$?
echo "expect DENIED -status: ${status}"
if [ $status -eq 0 ]; then
   echo "Error test${test_count}"
   err_count=$((err_count+1))
fi

echo "***************** Remove a read protected file"
test_count=$((test_count+1))
rm ${TEST_AREA}/filerp
status=$?
echo "expect PERMIT -status: ${status}"
if [ $status -ne 0 ]; then
   echo "Error test${test_count}"
   err_count=$((err_count+1))
fi

echo "***************** Move a read protected file"
python create_rule.py -a drop -t file -n 1 -f ${TEST_AREA}/filerp1 -p 4 > json_tmp_file
./build/bin/sr_test -f json_tmp_file
test_count=$((test_count+1))
mv ${TEST_AREA}/filerp1 ${TEST_AREA}/filerp_m
status=$?
echo "expect DENY -status: ${status}"
if [ $status -eq 0 ]; then
   echo "Error test${test_count}"
   err_count=$((err_count+1))
fi

echo "***************** Soft link a read protected file"
test_count=$((test_count+1))
ln -s ${TEST_AREA}/filerp1 ${TEST_AREA}/filerp_s
status=$?
echo "expect PERMIT -status: ${status}"
if [ $status -gt 0 ]; then
   echo "Error test${test_count}"
   err_count=$((err_count+1))
fi

echo "***************** Read a soft linked read protected file"
test_count=$((test_count+1))
cat ${TEST_AREA}/filerp_s > /dev/null
status=$?
echo "expect DENIED -status: ${status}"
if [ $status -eq 0 ]; then
   echo "Error test${test_count}"
   err_count=$((err_count+1))
fi

echo "***************** Hard link a read protected file"
test_count=$((test_count+1))
ln ${TEST_AREA}/filerp1 ${TEST_AREA}/filerp_l
status=$?
echo "expect DENY -status: ${status}"
if [ $status -eq 0 ]; then
   echo "Error test${test_count}"
   err_count=$((err_count+1))
fi

echo "***************** Copy read protected file"
test_count=$((test_count+1))
cp ${TEST_AREA}/filerp1 ${TEST_AREA}/filerp_c
status=$?
echo "expect DENY -status: ${status}"
if [ $status -eq 0 ]; then
   echo "Error test${test_count}"
   err_count=$((err_count+1))
fi

echo "***************************** open a read protected file to read **"
test_count=$((test_count+1))
python open_file.py -o r -f ${TEST_AREA}/filerp1
status=$?
echo "expect DENIED - status: ${status}"
if [ $status -eq 0 ]; then
   echo "Error test${test_count}"
   err_count=$((err_count+1))
fi

echo "******* Delete the rule ********* open a read protected file "
python create_rule.py > json_tmp_file
./build/bin/sr_test -f json_tmp_file
test_count=$((test_count+1))
python open_file.py -o r -f ${TEST_AREA}/filerp1
status=$?
echo "expect PERMIT - status: ${status}"
if [ $status -ne 0 ]; then
   echo "Error test${test_count}"
   err_count=$((err_count+1))
fi

echo "******* Create the read protect rule ********* open a read protected file "
python create_rule.py -a drop -t file -n 1 -f ${TEST_AREA}/filerp1 -p 4 > json_tmp_file
./build/bin/sr_test -f json_tmp_file
test_count=$((test_count+1))
python open_file.py -o r -f ${TEST_AREA}/filerp1
status=$?
echo "expect DENY - status: ${status}"
if [ $status -eq 0 ]; then
   echo "Error test${test_count}"
   err_count=$((err_count+1))
fi

echo "********* Read a file from an read protectd dir "
python create_rule.py -a drop -t file -n 1 -f ${TEST_AREA}/dirrp -p 4 > json_tmp_file
./build/bin/sr_test -f json_tmp_file
test_count=$((test_count+1))
cat ${TEST_AREA}/dirrp/file > /dev/null
status=$?
echo "expect DENIED -status: ${status}"
if [ $status -eq 0 ]; then
   echo "Error test${test_count}"
   err_count=$((err_count+1))
fi


echo "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% Write protected tests %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
echo "***************** Read from a write protected file"
python create_rule.py -a drop -t file -n 1 -f ${TEST_AREA}/filewp -p 2 > json_tmp_file
./build/bin/sr_test -f json_tmp_file
test_count=$((test_count+1))
cat ${TEST_AREA}/filewp > /dev/null
status=$?
echo "expect PERMIT -status: ${status}"
if [ $status -ne 0 ]; then
   echo "Error test${test_count}"
   err_count=$((err_count+1))
fi

echo "***************** Write to a write protected file"
test_count=$((test_count+1))
echo dddd > ${TEST_AREA}/filewp
status=$?
echo "expect DENIED -status: ${status}"
if [ $status -eq 0 ]; then
   echo "Error test${test_count}"
   err_count=$((err_count+1))
fi

echo "***************** Write to a write protected dir"
python create_rule.py -a drop -t file -n 1 -f ${TEST_AREA}/dirwp -p 2 > json_tmp_file
./build/bin/sr_test -f json_tmp_file
test_count=$((test_count+1))
echo dddd > ${TEST_AREA}/dirwp/file
status=$?
echo "expect DENIED -status: ${status}"
if [ $status -eq 0 ]; then
   echo "Error test${test_count}"
   err_count=$((err_count+1))
fi

echo "***************** Rm a write protected dir"
test_count=$((test_count+1))
rm -r ${TEST_AREA}/dirwp
status=$?
echo "expect DENIED -status: ${status}"
if [ $status -eq 0 ]; then
   echo "Error test${test_count}"
   err_count=$((err_count+1))
fi

echo "***************** Mv to a write protected dir"
echo aaaa > ${TEST_AREA}/file
test_count=$((test_count+1))
mv ${TEST_AREA}/file ${TEST_AREA}/dirwp/file_new
status=$?
echo "expect DENIED -status: ${status}"
if [ $status -eq 0 ]; then
   echo "Error test${test_count}"
   err_count=$((err_count+1))
fi

echo "***************** Soft link of a non protected file into a write proteced directory"
test_count=$((test_count+1))
cat kkkkk > ${TEST_AREA}/file_new
ln -s ${TEST_AREA}/file_new ${TEST_AREA}/dirwp/file_new
status=$?
echo "expect DENY -status: ${status}"
if [ $status -eq 0 ]; then
   echo "Error test${test_count}"
   err_count=$((err_count+1))
fi

echo "***************** Hard link of a non protected file into a write proteced directory"
test_count=$((test_count+1))
ln ${TEST_AREA}/file_new ${TEST_AREA}/dirwp/file_new
status=$?
echo "expect DENY -status: ${status}"
if [ $status -eq 0 ]; then
   echo "Error test${test_count}"
   err_count=$((err_count+1))
fi
rm -f ${TEST_AREA}/file_new

echo "***************** Rm a write protected file"
python create_rule.py -a drop -t file -n 1 -f ${TEST_AREA}/filewp -p 2 2 > json_tmp_file
./build/bin/sr_test -f json_tmp_file
test_count=$((test_count+1))
rm ${TEST_AREA}/filewp
status=$?
echo "expect DENIED -status: ${status}"
if [ $status -eq 0 ]; then
   echo "Error test${test_count}"
   err_count=$((err_count+1))
fi

echo "***************** Cp to a write protected file"
echo aaaa > ${TEST_AREA}/file
test_count=$((test_count+1))
cp ${TEST_AREA}/file ${TEST_AREA}/filewp
status=$?
echo "expect DENIED -status: ${status}"
if [ $status -eq 0 ]; then
   echo "Error test${test_count}"
   err_count=$((err_count+1))
fi

echo "***************** Mv to a write protected file"
echo aaaa > ${TEST_AREA}/file
test_count=$((test_count+1))
mv ${TEST_AREA}/file ${TEST_AREA}/filewp
status=$?
echo "expect DENIED -status: ${status}"
if [ $status -eq 0 ]; then
   echo "Error test${test_count}"
   err_count=$((err_count+1))
fi

echo "***************** Soft link of a write protected file"
test_count=$((test_count+1))
ln -s ${TEST_AREA}/filewp ${TEST_AREA}/file_new
status=$?
echo "expect PERMIT -status: ${status}"
if [ $status -ne 0 ]; then
   echo "Error test${test_count}"
   err_count=$((err_count+1))
fi

echo "***************** Update the Soft link of a write protected file"
test_count=$((test_count+1))
echo SSSSS >  ${TEST_AREA}/file_new
status=$?
echo "expect DENY -status: ${status}"
if [ $status -eq 0 ]; then
   echo "Error test${test_count}"
   err_count=$((err_count+1))
fi

echo "***************** Hard link of a write protected file"
rm ${TEST_AREA}/file_new
test_count=$((test_count+1))
ln ${TEST_AREA}/filewp ${TEST_AREA}/file_new
status=$?
echo "expect DENY -status: ${status}"
if [ $status -eq 0 ]; then
   echo "Error test${test_count}"
   err_count=$((err_count+1))
fi

echo "***************************** open a write protected file to write **"
test_count=$((test_count+1))
python open_file.py -o w -f ${TEST_AREA}/filewp
status=$?
echo "expect DENIED - status: ${status}"
if [ $status -eq 0 ]; then
   echo "Error test${test_count}"
   err_count=$((err_count+1))
fi

echo "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% Exec protected tests %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"

echo "***************************** Execute an exec protected file**"
python create_rule.py -a drop -t file -n 1 -f ${TEST_AREA}/filexp -p 1 > json_tmp_file
./build/bin/sr_test -f json_tmp_file
test_count=$((test_count+1))
cat ${TEST_AREA}/filexp > /dev/null
status=$?
echo "expect PERMIT - status: ${status}"
if [ $status -ne 0 ]; then
   echo "Error test${test_count}"
   err_count=$((err_count+1))
fi
${TEST_AREA}/filexp > /dev/null
status=$?
echo "expect DENIED - status: ${status}"
if [ $status -eq 0 ]; then
   echo "Error test${test_count}"
   err_count=$((err_count+1))
fi

python create_rule.py > json_tmp_file
./build/bin/sr_test -f json_tmp_file

echo "\nFinished ${test_count} tests"
if [ $err_count -eq 0 ]; then
   echo "Test SUCCESS!!"
   exit 0
else
   echo "Test FAILED ${err_count} errors !!"
   exit 1
fi


