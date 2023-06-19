# 简介

[![Compile Check](https://github.com/bobwenstudy/zephyr_polling/actions/workflows/github-actions-demo.yml/badge.svg)](https://github.com/bobwenstudy/zephyr_polling/actions/workflows/github-actions-demo.yml) [![Documentation Status](https://readthedocs.org/projects/zephyr-polling/badge/?version=latest)](https://zephyr-polling.readthedocs.io/en/latest/?badge=latest)

本项目目标是构建一个精简版的蓝牙协议栈。项目大量借鉴了[Zephyr Project](https://www.zephyrproject.org/)和[bobwenstudy/zephyr_polling (github.com)](https://github.com/bobwenstudy/zephyr_polling)的源码。

满足BLE peripheral+SMP功能的Code Size目标为24KB以内（Core CM0），RAM控制4KB以内。

截止于2023年6月19号，项目只实现了BLE peripheral功能，Code Size已经超了，后续优化。

目前Cortex-CM0下编译，整个协议栈的Code Size和RAM Size如下。

![image-20230619101432330](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230619101432330.png)

# 项目背景

作为一个蓝牙芯片从业者，市面的免费蓝牙协议栈大多是伴随操作系统发布，不管可移植性还是易用性都一般。BtStack很不错，但是是收费的。

对于蓝牙芯片开发而言，大多数做应用的同事接触到的都是Host的API，Host协议栈的学习成本和使用难度决定了蓝牙的应用广度。大多数蓝牙芯片都有自己的一套蓝牙Host协议栈，导致从A芯片切换到B芯片时，蓝牙应用人员需要花费大量时间去学习协议栈使用，进一步导致很多蓝牙feature无法被使用到。

所以本项目目标是构建一个简单好用的蓝牙协议栈，并确保项目尽量精简。保障协议栈基本功能时，蓝牙的各项feature都以宏隔开，方便后续功能定制化需要。



# 项目特点

## 轮询架构

项目不包含OS部分，项目移植非常方便。

## hci同步发送机制

蓝牙的HCI层是Host和Controller的交互接口，其行为模型为CMD/EVENT结构，一般要完成一个动作经常需要多个CMD/EVENT对，如果通过轮询机制实现，代码会很丑。在操作系统环境下，通过多线程的操作很好实现sync行为。

参考STM32的做法，在加大一定porting难度的代价下，在无OS情况下实现hci sync机制，大大降低了蓝牙HCI的使用成本。

## Zephyr GATT Service调用接口

Zephyr项目的GATT Service接口算是我接触下来比较好用的API模型了，本项目保留了这块机制。

# 系统架构

蓝牙协议栈为EasyBT的结构，系统总体架构参考Btstack的实现，总体结构如下图所示。

![image-20221125111329111](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20221125111329111.png)

如上图所示，系统主要分为5个部分，代码结构如下所示：

- **chipset**：各家厂商在使用之前需要进行一些配置，有些是因为芯片是rom化版本，需要加载patch，有些要配置RF参数，有些要配置蓝牙地址等。
- **example**：各种蓝牙例程，基本是照搬zephyr的来，当然会加入一些新的case。
- **platform**：移植时重点关注的部分，蓝牙协议栈运行需要用到一些平台资源，不同平台有不同实现方式，主要包括log、timer、storage_kv和HCI接口的实现。
- **porting**：程序的主入口，这些会将platform/chipset和协议栈接口进行绑定，并启动example，最后对协议栈进行调度。
- **src**：zephyr的蓝牙协议栈部分，具体实现蓝牙协议栈的具体细节。

```shell
EasyBT
 ├── chipset
 │   ├── csr8510_usb
 │   └── csr8910_uart
 ├── example
 │   ├── beacon
 │   ├── broadcaster
 │   ├── central
 │   ├── observer
 │   ├── peripheral
 │   ...
 ├── platform
 │   └── windows
 │   ...
 ├── porting
 │   ├── windows_libusb_win32
 │   └── windows_serial
 │   ...
 └── src
     ...
```





# 使用说明

## 环境搭建

目前暂时只支持Windows编译，最终生成exe，可以直接在PC上跑。

目前需要安装如下环境：

- [Python3](http://www.python.org/getit/)，用于Kconfig，代码格式化，RAM&ROM分析等，编译工具类都用这个。
- GCC环境，笔者用的msys64+mingw，用于编译生成exe，参考这个文章安装即可。[Win7下msys64安装mingw工具链 - Milton - 博客园 (cnblogs.com)](https://www.cnblogs.com/milton/p/11808091.html)。



### Python环境准备

python装好后，还需要安装一些环境，运行`python_require_env.py`脚本就会安装所有所需的python环境。

```shell
python python_require_env.py
```





## 编译说明

本项目都是由makefile组织编译的，编译整个项目只需要执行`make all`即可，调用`make help`可以查看帮助。

根据具体需要可以调整一些参数，目前Makefile支持如下参数配置。

- **APP**：选择example中的例程，默认选择为`beacon`。
- **PORT**：选择porting中的环境，也就是当前平台和HCI接口类型，默认选择为`windows_libusb_win32`。
- **CHIPSET**：选择chipset中的芯片种类，默认选择为`csr8510_usb`。

也就是可以通过如下指令来编译工程：

```shell
make all APP=beacon PORT=windows_libusb_win32 CHIPSET=csr8510_usb
```





## HCI Dongle部署

在PC环境下，常见的设备有USB设备和UART设备，下面分别对这两个设备进行部署。

### USB设备使用

为了能操作这些USB蓝牙dongle，默认使用的驱动是蓝牙的驱动。所以需要更改设备所使用的驱动。

- Step1：下载[Zadig](https://zadig.akeo.ie/)。
- Step2：菜单栏点击Options -> List All Devices。

![image-20221125133827682](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20221125133827682.png)

- Step3：通过下拉选中当前连接的蓝牙dongle，更换设备driver为`libusb-win32`，如下图所示，过一会就换好驱动了。

![image-20221125133953130](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20221125133953130.png)



### UART设备使用

这个直接看以下设备的串口号，在代码里面配置好后就可以正常使用了。（这块还没做，准备放在Makefile中操作）





## 支持芯片列表

makefile中配置**CHIPSET**，后续不断完善。


| 厂商                                       | chipset                                                      | 接口 | 蓝牙版本 | 类型      |
| ------------------------------------------ | ------------------------------------------------------------ | ---- | -------- | --------- |
| [CSR](https://www.qualcomm.cn/)            | [csr8510](https://detail.tmall.com/item.htm?abbucket=2&id=534662513906&ns=1&spm=a230r.1.14.1.2f6811a37qFFQU&skuId=4910946697067) | USB  | 4.0      | Dual Mode |
| [CSR](https://www.qualcomm.cn/)            | [csr8910](https://item.taobao.com/item.htm?spm=a1z09.2.0.0.6cd22e8dj2naR0&id=622836061708&_u=3m1kbkea372) | UART | 4.0      | Dual Mode |
| [炬芯-Actions](http://www.actions.com.cn/) | [ats2851](https://detail.tmall.com/item.htm?abbucket=2&id=534662513906&ns=1&spm=a230r.1.14.1.2f6811a37qFFQU&skuId=5111551883875) | USB  | 5.3      | Dual Mode |
| [Nordic](https://www.nordicsemi.com/)      | [pts_dongle](https://item.taobao.com/item.htm?spm=a1z09.2.0.0.6cd22e8dj2naR0&id=622836061708&_u=3m1kbkea372) | UART | 5.3      | LE Only   |





## 日志系统

参考btstack，系统支持多种debug方式，生成的日志文件保存在output/log目录下：

| 名称                 | 分析软件          | 备注                                                   |
| -------------------- | ----------------- | ------------------------------------------------------ |
| btsnoop(.cfa)        | frontline/eclipse | 分析蓝牙协议最好的一个协议存储格式                     |
| packet_logger(.pklg) | wireshark         | 暂不支持，苹果推出的一个日志分析格式，支持log+协议分析 |
| 日志(.log)           | 文本编辑器        | 将终端的日志保存成文件，方便离线分析                   |

![image-20221125112900757](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20221125112900757.png)





# Code Size分析说明

## 介绍

本项目是精简版协议栈，大家对Code Size和RAM Size非常关心，项目集成了CM0编译环境，以便大家评估协议栈大小。

项目以Cortex-CM0来对芯片进行Code Size和RAM Size进行分析。

## 环境搭建

目前暂时只支持CM0编译，最终生成elf，程序并不能运行，但是可以用于评估协议栈Code Size。

在安装好Windows环境基础上，还需要安装如下环境：

- [Arm GNU Toolchain](http://www.python.org/getit/)，ARM Toolchain，交叉工具链，用于编译项目。

## 编译说明

切换到CM0/GCC目录下，调整Makefile中的Toolchain路径，并执行`make all`即可。

![image-20230619101410703](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230619101410703.png)

![image-20230619101432330](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230619101432330.png)

### RAM_Report&ROM_Report

参考zephyr，对生成的elf进行分析，最终会生成ram.json和rom.json。这两个文件也可以导入到nordic的vscode环境下，可以借助其图形化工具进行分析。

![image-20221125112930355](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20221125112930355.png)

![image-20230619101514160](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230619101514160.png)



