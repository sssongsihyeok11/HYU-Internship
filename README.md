# HYU-Internship

**Understand basic homomorphic encryption operations**

## 0. Open ssh configuration file

https://wp.ecomong.net/visual-studio-code-remote-ssh-%EC%84%A4%EC%A0%95-%EB%B0%A9%EB%B2%95/

## 1. Install venv and pybind11

```bash
python3 -m venv venv
source venv/bin/activate
pip install pybind11
```

## 2. Clone repositories

```bash
git clone https://github.com/openfheorg/openfhe-development.git
git clone https://github.com/openfheorg/openfhe-python.git
```

## 3. Build openfhe-development

```bash
cd openfhe-development
mkdir build
cd build
```
```bash
cmake .. -DCMAKE_INSTALL_PREFIX=$VIRTUAL_ENV -DWITH_OPENMP=ON
```
```bash
make -j6
make install
```

## 4. Build openfhe-python

```bash
cd ~/intern/openfhe-python
```
```bash
mkdir build
cd build
```
```bash
cmake .. \
  -DCMAKE_PREFIX_PATH=$VIRTUAL_ENV \
  -DCMAKE_INSTALL_PREFIX=$VIRTUAL_ENV \
  -Dpybind11_DIR=$(python3 -m pybind11 --cmakedir)
```
```bash
make -j6
make install
```

## 5. Configure openfhe module

```bash
mkdir -p $VIRTUAL_ENV/lib/python3.12/site-packages/openfhe

mv $VIRTUAL_ENV/__init__.py \
   $VIRTUAL_ENV/lib/python3.12/site-packages/openfhe/

mv $VIRTUAL_ENV/openfhe.cpython*.so \
   $VIRTUAL_ENV/lib/python3.12/site-packages/openfhe/

echo 'export LD_LIBRARY_PATH=$VIRTUAL_ENV/lib:$LD_LIBRARY_PATH' >> $VIRTUAL_ENV/bin/activate
source $VIRTUAL_ENV/bin/activate
```
