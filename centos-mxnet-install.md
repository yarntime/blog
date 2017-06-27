#centos7 mxnet install


```
yum update

yum groupinstall -y "Development Tools" "Development Libraries"

yum install -y atlas atlas-devel opencv opencv-devel graphviz graphviz-devel

ln -s /usr/lib64/atlas/* /usr/lib64/

git clone --recursive https://github.com/dmlc/mxnet

cd mxnet

export MXNET_HOME=`pwd`

vi mshadow/make/mshadow.mk

// change  -lcblas to -lsatlas in line 77

make -j4

// test
cd example/image-classification/
python train_mnist.py


// install python
cd $MXNET_HOME/python
python setup.py install

```