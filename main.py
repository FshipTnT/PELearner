# ///////////////////////////////////////////////////////////////
#
# BY: WANDERSON M.PIMENTA
# PROJECT MADE WITH: Qt Designer and PySide6
# V: 1.0.0
#
# This project can be used freely for all uses, as long as they maintain the
# respective credits only in the Python scripts, any information in the visual
# interface (GUI) can be modified without any implication.
#
# There are limitations on Qt licenses if you want to use your products
# commercially, I recommend reading them on the official website:
# https://doc.qt.io/qtforpython/licenses.html
#
# ///////////////////////////////////////////////////////////////

import sys
import os
import platform

# IMPORT / GUI AND MODULES AND WIDGETS
# ///////////////////////////////////////////////////////////////
import peutils

from modules import *
from widgets import *
import pathlib
import pefile
import capstone
import hashlib
os.environ["QT_FONT_DPI"] = "96" # FIX Problem for High DPI and Scale above 100%

# SET AS GLOBAL WIDGETS
# ///////////////////////////////////////////////////////////////
widgets = None

class MainWindow(QMainWindow):
    def __init__(self):
        QMainWindow.__init__(self)

        # SET AS GLOBAL WIDGETS
        # ///////////////////////////////////////////////////////////////
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        global widgets
        widgets = self.ui

        # USE CUSTOM TITLE BAR | USE AS "False" FOR MAC OR LINUX
        # ///////////////////////////////////////////////////////////////
        Settings.ENABLE_CUSTOM_TITLE_BAR = True


        # current path
        self.current_path = pathlib.Path().absolute().as_posix()

        # APP NAME
        # ///////////////////////////////////////////////////////////////
        title = "PE文件逆向分析教学演示系统"
        description = "PE文件逆向分析教学演示系统"
        # APPLY TEXTS
        self.setWindowTitle(title)
        widgets.titleRightInfo.setText(description)

        # TOGGLE MENU
        # ///////////////////////////////////////////////////////////////
        widgets.toggleButton.clicked.connect(lambda: UIFunctions.toggleMenu(self, True))

        # SET UI DEFINITIONS
        # ///////////////////////////////////////////////////////////////
        UIFunctions.uiDefinitions(self)

        # QTableWidget PARAMETERS
        # ///////////////////////////////////////////////////////////////
        widgets.tableWidget.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        # BUTTONS CLICK
        # ///////////////////////////////////////////////////////////////

        # LEFT MENUS
        widgets.btn_home.clicked.connect(self.buttonClick)
        widgets.btn_show.clicked.connect(self.buttonClick)
        widgets.btn_reverse.clicked.connect(self.buttonClick)
        widgets.btn_ioInfo.clicked.connect(self.buttonClick)
        widgets.btn_cases.clicked.connect(self.buttonClick)

        # TOP MENUS
        widgets.btn_theme.clicked.connect(self.buttonClick)
        widgets.btn_support.clicked.connect(self.buttonClick)
        widgets.btn_link.clicked.connect(self.buttonClick)

        #page1
        widgets.pushButton_3.clicked.connect(self.on_brower)
        widgets.pushButton_4.clicked.connect(self.on_execute)

        #page2
        widgets.comboBox_6.currentIndexChanged.connect(self.on_comboBox_selected)

        #page4
        widgets.comboBox_2.currentIndexChanged.connect(self.on_comboBox_selected)

        # EXTRA LEFT BOX
        def openCloseLeftBox():
            UIFunctions.toggleLeftBox(self, True)

        widgets.extraCloseColumnBtn.clicked.connect(openCloseLeftBox)

        # EXTRA RIGHT BOX
        def openCloseRightBox():
            UIFunctions.toggleRightBox(self, True)
        widgets.settingsTopBtn.clicked.connect(openCloseRightBox)

        # SHOW APP
        # ///////////////////////////////////////////////////////////////
        self.show()

        # SET CUSTOM THEME
        # ////////////////////////////////////////////////  ///////////////
        if getattr(sys, 'frozen', False):
            absPath = os.path.dirname(os.path.abspath(sys.executable))
        elif __file__:
            absPath = os.path.dirname(os.path.abspath(__file__))
        self.absPath = absPath
        self.useCustomTheme = True
        themeFile = "themes\py_dracula_light.qss"

        # SET THEME AND HACKS
        if self.useCustomTheme:
            # LOAD AND APPLY STYLE
            UIFunctions.theme(self, themeFile, True)

            # SET HACKS
            AppFunctions.setThemeHack(self)

        # SET HOME PAGE AND SELECT MENU
        # ///////////////////////////////////////////////////////////////
        widgets.stackedWidget.setCurrentWidget(widgets.home)
        widgets.btn_home.setStyleSheet(UIFunctions.selectMenu(widgets.btn_home.styleSheet()))


    # BUTTONS CLICK

    # Post here your functions for clicked buttons
    # ///////////////////////////////////////////////////////////////
    def buttonClick(self):
        # GET BUTTON CLICKED
        btn = self.sender()
        btnName = btn.objectName()

        # btn_home
        if btnName == "btn_home":
            widgets.stackedWidget.setCurrentWidget(widgets.home)
            UIFunctions.resetStyle(self, btnName)
            btn.setStyleSheet(UIFunctions.selectMenu(btn.styleSheet()))

        # btn_show
        if btnName == "btn_show":
            widgets.stackedWidget.setCurrentWidget(widgets.page_show)
            UIFunctions.resetStyle(self, btnName)
            btn.setStyleSheet(UIFunctions.selectMenu(btn.styleSheet()))

        # btn_reverse
        if btnName == "btn_reverse":
            widgets.stackedWidget.setCurrentWidget(widgets.reverse) # SET PAGE
            UIFunctions.resetStyle(self, btnName) # RESET ANOTHERS BUTTONS SELECTED
            btn.setStyleSheet(UIFunctions.selectMenu(btn.styleSheet())) # SELECT MENU

        # btn_ioInfo
        if btnName == "btn_ioInfo":
            widgets.stackedWidget.setCurrentWidget(widgets.page_ioInfo)  # SET PAGE
            UIFunctions.resetStyle(self, btnName)  # RESET ANOTHERS BUTTONS SELECTED
            btn.setStyleSheet(UIFunctions.selectMenu(btn.styleSheet()))  # SELECT MENU

        # btn_cases
        if btnName == "btn_cases":
            widgets.stackedWidget.setCurrentWidget(widgets.page_cases)  # SET PAGE
            UIFunctions.resetStyle(self, btnName)  # RESET ANOTHERS BUTTONS SELECTED
            btn.setStyleSheet(UIFunctions.selectMenu(btn.styleSheet()))  # SELECT MENU

        # btn_theme
        if btnName == "btn_theme":
            if self.useCustomTheme:
                themeFile = os.path.abspath(os.path.join(self.absPath, "themes\py_dracula_dark.qss"))
                UIFunctions.theme(self, themeFile, True)

                # SET HACKS
                AppFunctions.setThemeHack(self)
                self.useCustomTheme = False
            else:
                themeFile = os.path.abspath(os.path.join(self.absPath, "themes\py_dracula_light.qss"))
                UIFunctions.theme(self, themeFile, True)

                # SET HACKS
                AppFunctions.setThemeHack(self)
                self.useCustomTheme = True

        # btn_support
        if btnName == "btn_support":
            filename = "guide.docx"
            if os.path.exists(filename):
                os.startfile(filename)
            else:
                print(f"guide.docx is not exist")

        # btn_link
        if btnName == "btn_link":
            url = QUrl("https://github.com/FshipTnT/PELearner")
            QDesktopServices.openUrl(url)

        # PRINT BTN NAME
        print(f'Button "{btnName}" pressed!')

    def on_brower(self):
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        self.filepath, _ = QFileDialog.getOpenFileName(
            window,
            "Select a file",
            self.current_path,
            "Executable files (*.exe *.pe *.dll);;All files (*.*)",
            options=options
        )
        if self.filepath:
            widgets.lineEdit_2.setText(self.filepath)
        else:
            print("No Select")

    def on_execute(self):
        # try:
            self.pe = pefile.PE(self.filepath)
            self.show_baseinfo(self.pe)
            self.show_hashinfo(self.pe)
            self.section_data = []
            self.section_data.clear()
            for section in self.pe.sections:
                # decode() 方法将字节串转换为字符串类型
                # 节的名称后面可能会带有一些空字符（\x00），因此需要使用 rstrip('\x00') 方法去掉末尾的空字符
                self.section_data.append(section.Name.decode().rstrip('\x00'))
            self.show_treeview()
            self.show_ascii()
            self.show_reverse()
            self.show_sections_combobox()
            self.show_secion_table()
            self.show_data_direction()
            self.show_import_info()
            print("success")
        # except:
        #     print("no executable file")

    def show_baseinfo(self, pe):
        try:
            widgets.label_4.setText(os.path.basename(self.filepath))
            widgets.label_5.setText(str(os.path.getsize(self.filepath)) + "byte")
            if pe.is_dll():
                widgets.checkBox_2.setChecked(True)
            if peutils.is_probably_packed(pe):
                widgets.checkBox.setChecked(True)
        except:
            print("error found in show_baseinfo")

    def show_hashinfo(self, pe):
        try:
            print('MD5:', self.get_file_hash(self.filepath, 'md5'))
            print('SHA1:', self.get_file_hash(self.filename, 'sha1'))
            print('SHA256:', self.get_file_hash(self.filename, 'sha256'))
            widgets.label_7.setText(self.get_file_hash(self.filepath, 'md5'))
            widgets.label_9.setText(self.get_file_hash(self.filepath, 'sha1'))
            widgets.label_11.setText(self.get_file_hash(self.filepath, 'sha256'))
        except:
            print("error found in show_hashinfo")

    def get_file_hash(self, filename, hash_type):
        """计算文件的哈希值"""
        with open(filename, 'rb') as f:
            if hash_type == 'md5':
                hash_obj = hashlib.md5()
            elif hash_type == 'sha1':
                hash_obj = hashlib.sha1()
            elif hash_type == 'sha256':
                hash_obj = hashlib.sha256()
            else:
                return None
            while True:
                data = f.read(4096)
                if not data:
                    break
                hash_obj.update(data)
            return hash_obj.hexdigest()

    def show_treeview(self):
        try:
            root = QTreeWidgetItem(widgets.treeWidget, [os.path.basename(self.filepath)])
            IMAGE_DOS_HEADER = QTreeWidgetItem(root, ["IMAGE_DOS_HEADER"])
            DOS_Stub_Program = QTreeWidgetItem(root, ['DOS_Stub_Program'])
            IMAGE_NT_HEADER = QTreeWidgetItem(root, ['IMAGE_NT_HEADER'])
            Signature = QTreeWidgetItem(IMAGE_NT_HEADER, ['Signature'])
            IMAGE_FILE_HEADER = QTreeWidgetItem(IMAGE_NT_HEADER, ['IMAGE_FILE_HEADER'])
            IMAGE_OPTIONAL_TABLE = QTreeWidgetItem(IMAGE_NT_HEADER, ['IMAGE_OPTIONAL_HEADER'])
            DATA_DIRECTION_TABLE = QTreeWidgetItem(root, ['DATA_DIRECTION_TABLE'])
            SECTION_TABLE = QTreeWidgetItem(root, ['SECTION_TABLE'])
            SECTIONS = QTreeWidgetItem(root, ['SECTIONS'])
            for sd in self.section_data:
                QTreeWidgetItem(SECTIONS, [sd])
            widgets.treeWidget.itemClicked.connect(self.treeview_clicked)
        except:
            print("error found in show_treeview")

    def treeview_clicked(self, item, column):
        select_name = item.text(column)
        if select_name == "IMAGE_DOS_HEADER":
            idx = 0
            idy = 2
            self.highlight_character(idx, idy)
            self.dos_header_details()
            # text = widgets.textBrowser.document().findBlockByLineNumber(33).text()
            # 创建一个QTextCursor对象，并将其设置为第3行的开头
            cursor = QTextCursor(widgets.textBrowser.document().findBlockByLineNumber(idx))
            # 将QTextBrowser的光标设置为QTextCursor的位置
            widgets.textBrowser.setTextCursor(cursor)
            # 设置高亮显示
            highlight_format = cursor.charFormat()
            highlight_format.setBackground(Qt.yellow)
            cursor.setCharFormat(highlight_format)
        if select_name == "DOS_Stub_Program":
            idx = 4
            idy = 2
            self.highlight_character(idx, idy)
            # # text = widgets.textBrowser.document().findBlockByLineNumber(33).text()
            # # 创建一个QTextCursor对象，并将其设置为第3行的开头
            # cursor = QTextCursor(widgets.textBrowser.document().findBlockByLineNumber(idx))
            # # 将QTextBrowser的光标设置为QTextCursor的位置
            # widgets.textBrowser.setTextCursor(cursor)
        if select_name == "SECTION_TABLE":
            idx = int((self.pe.OPTIONAL_HEADER.get_file_offset() + self.pe.FILE_HEADER.SizeOfOptionalHeader) / 16)
            idy = int((self.pe.OPTIONAL_HEADER.get_file_offset() + self.pe.FILE_HEADER.SizeOfOptionalHeader) % 16) + 2
            self.highlight_character(idx, idy)
            # text = widgets.textBrowser.document().findBlockByLineNumber(33).text()
            # 创建一个QTextCursor对象，并将其设置为第3行的开头
            cursor = QTextCursor(widgets.textBrowser.document().findBlockByLineNumber(idx))
            # 将QTextBrowser的光标设置为QTextCursor的位置
            widgets.textBrowser.setTextCursor(cursor)
            print("SECTION_TABLE")
        if select_name == "IMAGE_NT_HEADER":
            idx = int((self.pe.FILE_HEADER.get_file_offset() - 4) / 16)
            idy = int((self.pe.FILE_HEADER.get_file_offset() - 4) % 16) + 2
            self.highlight_character(idx, idy)
            # text = widgets.textBrowser.document().findBlockByLineNumber(33).text()
            # 创建一个QTextCursor对象，并将其设置为第3行的开头
            cursor = QTextCursor(widgets.textBrowser.document().findBlockByLineNumber(idx))
            # 将QTextBrowser的光标设置为QTextCursor的位置
            widgets.textBrowser.setTextCursor(cursor)
            print("IMAGE_NT_HEADER")
        if select_name == "Signature":
            idx = int((self.pe.FILE_HEADER.get_file_offset() - 4) / 16)
            idy = int((self.pe.FILE_HEADER.get_file_offset() - 4) % 16) + 2
            self.highlight_character(idx, idy)
            # text = widgets.textBrowser.document().findBlockByLineNumber(33).text()
            # 创建一个QTextCursor对象，并将其设置为第3行的开头
            cursor = QTextCursor(widgets.textBrowser.document().findBlockByLineNumber(idx))
            # 将QTextBrowser的光标设置为QTextCursor的位置
            widgets.textBrowser.setTextCursor(cursor)
            print("Signature")
        if select_name == "IMAGE_FILE_HEADER":
            idx = int(self.pe.FILE_HEADER.get_file_offset() / 16)
            idy = int(self.pe.FILE_HEADER.get_file_offset() % 16) + 2
            self.highlight_character(idx, idy)
            self.file_header_details()
            print("IMAGE_FILE_HEADER")
        if select_name == "IMAGE_OPTIONAL_HEADER":
            idx = int(self.pe.OPTIONAL_HEADER.get_file_offset() / 16)
            idy = int(self.pe.OPTIONAL_HEADER.get_file_offset() % 16) + 2
            self.highlight_character(idx, idy)
            self.optional_header_detail()
            # text = widgets.textBrowser.document().findBlockByLineNumber(33).text()
            # 创建一个QTextCursor对象，并将其设置为第3行的开头
            cursor = QTextCursor(widgets.textBrowser.document().findBlockByLineNumber(idx))
            # 将QTextBrowser的光标设置为QTextCursor的位置
            widgets.textBrowser.setTextCursor(cursor)
            print("IMAGE_OPTIONAL_HEADER")
        if select_name == "DATA_DIRECTION_TABLE":
            idx = int((self.pe.OPTIONAL_HEADER.get_file_offset() + self.pe.FILE_HEADER.SizeOfOptionalHeader) / 16 - 8)
            idy = int((self.pe.OPTIONAL_HEADER.get_file_offset() + self.pe.FILE_HEADER.SizeOfOptionalHeader) % 16 - 8) + 2
            self.highlight_character(idx, idy)
            # text = widgets.textBrowser.document().findBlockByLineNumber(33).text()
            # 创建一个QTextCursor对象，并将其设置为第3行的开头
            cursor = QTextCursor(widgets.textBrowser.document().findBlockByLineNumber(idx))
            # 将QTextBrowser的光标设置为QTextCursor的位置
            widgets.textBrowser.setTextCursor(cursor)
            print("DATA_DIRECTION_TABLE")
        if select_name == "SECTIONS":
            idx = int(self.pe.sections[0].PointerToRawData / 16)
            idy = int(self.pe.sections[0].PointerToRawData % 16) + 2
            self.highlight_character(idx, idy)
            # text = widgets.textBrowser.document().findBlockByLineNumber(33).text()
            # 创建一个QTextCursor对象，并将其设置为第3行的开头
            cursor = QTextCursor(widgets.textBrowser.document().findBlockByLineNumber(idx))
            # 将QTextBrowser的光标设置为QTextCursor的位置
            widgets.textBrowser.setTextCursor(cursor)
            print("SECTIONS")
        if select_name in self.section_data:
            i = self.find_index(self.section_data, select_name)
            idx = int(self.pe.sections[i].PointerToRawData / 16)
            idy = int(self.pe.sections[i].PointerToRawData % 16) + 2
            self.highlight_character(idx, idy)
            # text = widgets.textBrowser.document().findBlockByLineNumber(33).text()
            # 创建一个QTextCursor对象，并将其设置为第3行的开头
            cursor = QTextCursor(widgets.textBrowser.document().findBlockByLineNumber(idx))
            # 将QTextBrowser的光标设置为QTextCursor的位置
            widgets.textBrowser.setTextCursor(cursor)
            print(select_name)

    def find_index(self, array, target):
        for i in range(len(array)):
            if array[i] == target:
                return i
        return -1

    def highlight_character(self, line_number, char_index):
        cursor = widgets.textBrowser.textCursor()

        # 将光标移动到第三行第四个字符处
        cursor.movePosition(QTextCursor.Start)
        for i in range(line_number):
            cursor.movePosition(QTextCursor.Down)
        for i in range(char_index):
            cursor.movePosition(QTextCursor.WordRight)

        # 创建一个QTextCharFormat对象并设置背景色
        highlight_format = QTextCharFormat()
        highlight_format.setBackground(Qt.yellow)

        # 将光标应用到格式
        cursor.setPosition(cursor.position(), QTextCursor.MoveAnchor)
        cursor.movePosition(QTextCursor.WordRight, QTextCursor.KeepAnchor, n=2)
        cursor.mergeCharFormat(highlight_format)

        # 将文本浏览器滚动到光标位置
        widgets.textBrowser.setTextCursor(cursor)
        widgets.textBrowser.ensureCursorVisible()

    def remove_highlight(self):
        pass

    def dos_header_details(self):
        # e_magic	2	指示文件是否为DOS可执行文件的标志
        # e_cblp	2	文件的最后一页的字节数
        # e_cp	2	文件中的页数
        # e_crlc	2	重定位表中的项数
        # e_cparhdr	2	头部的段数
        # e_minalloc	2	所需的最小附加段字节数
        # e_maxalloc	2	所需的最大附加段字节数
        # e_ss	2	初始的堆栈段值
        # e_sp	2	初始的堆栈指针值
        # e_csum	2	校验和
        # e_ip	2	初始的程序指针值
        # e_cs	2	初始的代码段值
        # e_lfarlc	2	重定位表的文件偏移量
        # e_ovno	2	覆盖号
        # e_res	8	保留字段
        # e_oemid	2	OEM标识符
        # e_oeminfo	2	OEM信息
        # e_res2	20	保留字段
        # e_lfanew	4	PE头的文件偏移量
        # 清除原有数据
        widgets.tableWidget_data.clearContents()
        # 添加数据
        item = widgets.tableWidget_data.horizontalHeaderItem(0)
        item.setText(QCoreApplication.translate("MainWindow", u"Dos Header", None));
        widgets.tableWidget_data.setItem(0, 0, QTableWidgetItem('e_magic'))
        widgets.tableWidget_data.setItem(0, 1, QTableWidgetItem(hex(self.pe.DOS_HEADER.e_magic)))
        widgets.tableWidget_data.setItem(1, 0, QTableWidgetItem('e_cblp'))
        widgets.tableWidget_data.setItem(1, 1, QTableWidgetItem(hex(self.pe.DOS_HEADER.e_cblp)))
        widgets.tableWidget_data.setItem(2, 0, QTableWidgetItem('e_cp'))
        widgets.tableWidget_data.setItem(2, 1, QTableWidgetItem(hex(self.pe.DOS_HEADER.e_cp)))
        widgets.tableWidget_data.setItem(3, 0, QTableWidgetItem('e_crlc'))
        widgets.tableWidget_data.setItem(3, 1, QTableWidgetItem(hex(self.pe.DOS_HEADER.e_crlc)))
        widgets.tableWidget_data.setItem(4, 0, QTableWidgetItem('e_cparhdr'))
        widgets.tableWidget_data.setItem(4, 1, QTableWidgetItem(hex(self.pe.DOS_HEADER.e_cparhdr)))
        widgets.tableWidget_data.setItem(5, 0, QTableWidgetItem('e_minalloc'))
        widgets.tableWidget_data.setItem(5, 1, QTableWidgetItem(hex(self.pe.DOS_HEADER.e_minalloc)))
        widgets.tableWidget_data.setItem(6, 0, QTableWidgetItem('e_maxalloc'))
        widgets.tableWidget_data.setItem(6, 1, QTableWidgetItem(hex(self.pe.DOS_HEADER.e_maxalloc)))
        widgets.tableWidget_data.setItem(7, 0, QTableWidgetItem('e_ss'))
        widgets.tableWidget_data.setItem(7, 1, QTableWidgetItem(hex(self.pe.DOS_HEADER.e_ss)))
        widgets.tableWidget_data.setItem(8, 0, QTableWidgetItem('e_sp'))
        widgets.tableWidget_data.setItem(8, 1, QTableWidgetItem(hex(self.pe.DOS_HEADER.e_sp)))
        widgets.tableWidget_data.setItem(9, 0, QTableWidgetItem('e_csum'))
        widgets.tableWidget_data.setItem(9, 1, QTableWidgetItem(hex(self.pe.DOS_HEADER.e_csum)))
        widgets.tableWidget_data.setItem(10, 0, QTableWidgetItem('e_ip'))
        widgets.tableWidget_data.setItem(10, 1, QTableWidgetItem(hex(self.pe.DOS_HEADER.e_ip)))
        widgets.tableWidget_data.setItem(11, 0, QTableWidgetItem('e_cs'))
        widgets.tableWidget_data.setItem(11, 1, QTableWidgetItem(hex(self.pe.DOS_HEADER.e_cs)))
        widgets.tableWidget_data.setItem(12, 0, QTableWidgetItem('e_lfarlc'))
        widgets.tableWidget_data.setItem(12, 1, QTableWidgetItem(hex(self.pe.DOS_HEADER.e_lfarlc)))
        widgets.tableWidget_data.setItem(13, 0, QTableWidgetItem('e_ovno'))
        widgets.tableWidget_data.setItem(13, 1, QTableWidgetItem(hex(self.pe.DOS_HEADER.e_ovno)))
        widgets.tableWidget_data.setItem(14, 0, QTableWidgetItem('e_res'))
        widgets.tableWidget_data.setItem(14, 1, QTableWidgetItem(str(self.pe.DOS_HEADER.e_res)))
        widgets.tableWidget_data.setItem(15, 0, QTableWidgetItem('e_oemid'))
        widgets.tableWidget_data.setItem(15, 1, QTableWidgetItem(hex(self.pe.DOS_HEADER.e_oemid)))
        widgets.tableWidget_data.setItem(16, 0, QTableWidgetItem('e_oeminfo'))
        widgets.tableWidget_data.setItem(16, 1, QTableWidgetItem(hex(self.pe.DOS_HEADER.e_oeminfo)))
        widgets.tableWidget_data.setItem(17, 0, QTableWidgetItem('e_res2'))
        widgets.tableWidget_data.setItem(17, 1, QTableWidgetItem(str(self.pe.DOS_HEADER.e_res2)))
        widgets.tableWidget_data.setItem(18, 0, QTableWidgetItem('e_lfanew'))
        widgets.tableWidget_data.setItem(18, 1, QTableWidgetItem(hex(self.pe.DOS_HEADER.e_lfanew)))

    def file_header_details(self):
        # Machine	2	CPU架构类型
        # NumberOfSections	2	节表的数量
        # TimeDateStamp	4	文件创建时间戳
        # PointerToSymbolTable	4	COFF符号表的文件偏移量
        # NumberOfSymbols	4	COFF符号表中符号的数量
        # SizeOfOptionalHeader	2	可选头的字节数
        # Characteristics	2	文件属性标志
        # 清除原有数据
        widgets.tableWidget_data.clearContents()
        #添加数据
        item = widgets.tableWidget_data.horizontalHeaderItem(0)
        item.setText(QCoreApplication.translate("MainWindow", u"File Header", None));
        widgets.tableWidget_data.setItem(0, 0, QTableWidgetItem('Machine'))
        widgets.tableWidget_data.setItem(0, 1, QTableWidgetItem(hex(self.pe.FILE_HEADER.Machine)))
        widgets.tableWidget_data.setItem(1, 0, QTableWidgetItem('NumberofSections'))
        widgets.tableWidget_data.setItem(1, 1, QTableWidgetItem(hex(self.pe.FILE_HEADER.NumberOfSections)))
        widgets.tableWidget_data.setItem(2, 0, QTableWidgetItem('TimeDateStamp'))
        widgets.tableWidget_data.setItem(2, 1, QTableWidgetItem(hex(self.pe.FILE_HEADER.TimeDateStamp)))
        widgets.tableWidget_data.setItem(3, 0, QTableWidgetItem('PointerToSymbolTable'))
        widgets.tableWidget_data.setItem(3, 1, QTableWidgetItem(hex(self.pe.FILE_HEADER.PointerToSymbolTable)))
        widgets.tableWidget_data.setItem(4, 0, QTableWidgetItem('NumberOfSymbols'))
        widgets.tableWidget_data.setItem(4, 1, QTableWidgetItem(hex(self.pe.FILE_HEADER.NumberOfSymbols)))
        widgets.tableWidget_data.setItem(5, 0, QTableWidgetItem('SizeOfOptionalHeader'))
        widgets.tableWidget_data.setItem(5, 1, QTableWidgetItem(hex(self.pe.FILE_HEADER.SizeOfOptionalHeader)))
        widgets.tableWidget_data.setItem(6, 0, QTableWidgetItem('Characteristics'))
        widgets.tableWidget_data.setItem(6, 1, QTableWidgetItem(hex(self.pe.FILE_HEADER.Characteristics)))

    def optional_header_detail(self):
        # Magic   2   可选头的格式标识
        # MajorLinkerVersion	1	链接器主版本号
        # MinorLinkerVersion	1	链接器次版本号
        # SizeOfCode	4	执行代码的大小
        # SizeOfInitializedData	4	已初始化数据的大小
        # SizeOfUninitializedData	4	未初始化数据的大小
        # AddressOfEntryPoint	4	程序入口点的RVA地址
        # BaseOfCode	4	代码段的RVA地址
        # BaseOfData	4	数据段的RVA地址
        # ImageBase	8	PE文件的建议加载地址
        # SectionAlignment	4	节的对齐方式
        # FileAlignment	4	文件的对齐方式
        # MajorOperatingSystemVersion	2	操作系统主版本号
        # MinorOperatingSystemVersion	2	操作系统次版本号
        # MajorImageVersion	2	PE文件主版本号
        # MinorImageVersion	2	PE文件次版本号
        # MajorSubsystemVersion	2	子系统主版本号
        # MinorSubsystemVersion	2	子系统次版本号
        # Win32VersionValue	4	Win32版本值
        # SizeOfImage	4	PE文件的映像大小
        # SizeOfHeaders	4	文件头和节表的总大小
        # CheckSum	4	校验和
        # Subsystem	2	子系统类型
        # DllCharacteristics	2	DLL文件属性标志
        # SizeOfStackReserve	8	程序堆栈的大小
        # SizeOfStackCommit	8	程序堆栈的初始提交大小
        # SizeOfHeapReserve	8	程序堆的大小
        # SizeOfHeapCommit	8	程序堆的初始提交大小
        # LoaderFlags	4	加载器标志
        # NumberOfRvaAndSizes	4	数据目录项的数量
        # 清除原有数据
        widgets.tableWidget_data.clearContents()
        # 添加数据
        item = widgets.tableWidget_data.horizontalHeaderItem(0)
        item.setText(QCoreApplication.translate("MainWindow", u"Optional Header", None));
        widgets.tableWidget_data.setItem(0, 0, QTableWidgetItem('Magic'))
        widgets.tableWidget_data.setItem(0, 1, QTableWidgetItem(hex(self.pe.OPTIONAL_HEADER.Magic)))
        widgets.tableWidget_data.setItem(1, 0, QTableWidgetItem('MajorLinkerVersion'))
        widgets.tableWidget_data.setItem(1, 1, QTableWidgetItem(hex(self.pe.OPTIONAL_HEADER.MajorLinkerVersion)))
        widgets.tableWidget_data.setItem(2, 0, QTableWidgetItem('MinorLinkerVersion'))
        widgets.tableWidget_data.setItem(2, 1, QTableWidgetItem(hex(self.pe.OPTIONAL_HEADER.MinorLinkerVersion)))
        widgets.tableWidget_data.setItem(3, 0, QTableWidgetItem('SizeOfCode'))
        widgets.tableWidget_data.setItem(3, 1, QTableWidgetItem(hex(self.pe.OPTIONAL_HEADER.SizeOfCode)))
        widgets.tableWidget_data.setItem(4, 0, QTableWidgetItem('SizeOfInitializedData'))
        widgets.tableWidget_data.setItem(4, 1, QTableWidgetItem(hex(self.pe.OPTIONAL_HEADER.SizeOfInitializedData)))
        widgets.tableWidget_data.setItem(5, 0, QTableWidgetItem('SizeOfUninitializedData'))
        widgets.tableWidget_data.setItem(5, 1, QTableWidgetItem(hex(self.pe.OPTIONAL_HEADER.SizeOfUninitializedData)))
        widgets.tableWidget_data.setItem(6, 0, QTableWidgetItem('AddressOfEntryPoint'))
        widgets.tableWidget_data.setItem(6, 1, QTableWidgetItem(hex(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint)))
        widgets.tableWidget_data.setItem(7, 0, QTableWidgetItem('BaseOfCode'))
        widgets.tableWidget_data.setItem(7, 1, QTableWidgetItem(hex(self.pe.OPTIONAL_HEADER.BaseOfCode)))
        widgets.tableWidget_data.setItem(8, 0, QTableWidgetItem('BaseOfData'))
        widgets.tableWidget_data.setItem(8, 1, QTableWidgetItem(hex(self.pe.OPTIONAL_HEADER.BaseOfData)))
        widgets.tableWidget_data.setItem(9, 0, QTableWidgetItem('ImageBase'))
        widgets.tableWidget_data.setItem(9, 1, QTableWidgetItem(hex(self.pe.OPTIONAL_HEADER.ImageBase)))
        widgets.tableWidget_data.setItem(10, 0, QTableWidgetItem('SectionAlignment'))
        widgets.tableWidget_data.setItem(10, 1, QTableWidgetItem(hex(self.pe.OPTIONAL_HEADER.SectionAlignment)))
        widgets.tableWidget_data.setItem(11, 0, QTableWidgetItem('FileAlignment'))
        widgets.tableWidget_data.setItem(11, 1, QTableWidgetItem(hex(self.pe.OPTIONAL_HEADER.FileAlignment)))
        widgets.tableWidget_data.setItem(12, 0, QTableWidgetItem('MajorOperatingSystemVersion'))
        widgets.tableWidget_data.setItem(12, 1, QTableWidgetItem(hex(self.pe.OPTIONAL_HEADER.MajorOperatingSystemVersion)))
        widgets.tableWidget_data.setItem(13, 0, QTableWidgetItem('MinorOperatingSystemVersion'))
        widgets.tableWidget_data.setItem(13, 1, QTableWidgetItem(hex(self.pe.OPTIONAL_HEADER.MinorOperatingSystemVersion)))
        widgets.tableWidget_data.setItem(14, 0, QTableWidgetItem('MajorImageVersion'))
        widgets.tableWidget_data.setItem(14, 1, QTableWidgetItem(hex(self.pe.OPTIONAL_HEADER.MajorImageVersion)))
        widgets.tableWidget_data.setItem(15, 0, QTableWidgetItem('MinorImageVersion'))
        widgets.tableWidget_data.setItem(15, 1, QTableWidgetItem(hex(self.pe.OPTIONAL_HEADER.MinorImageVersion)))
        widgets.tableWidget_data.setItem(16, 0, QTableWidgetItem('MajorSubsystemVersion'))
        widgets.tableWidget_data.setItem(16, 1, QTableWidgetItem(hex(self.pe.OPTIONAL_HEADER.MajorSubsystemVersion)))
        widgets.tableWidget_data.setItem(17, 0, QTableWidgetItem('MinorSubsystemVersion'))
        widgets.tableWidget_data.setItem(17, 1, QTableWidgetItem(hex(self.pe.OPTIONAL_HEADER.MinorSubsystemVersion)))
        widgets.tableWidget_data.setItem(18, 0, QTableWidgetItem('Win32VersionValue'))
        widgets.tableWidget_data.setItem(18, 1, QTableWidgetItem(hex(self.pe.OPTIONAL_HEADER.Reserved1)))
        widgets.tableWidget_data.setItem(19, 0, QTableWidgetItem('SizeOfImage'))
        widgets.tableWidget_data.setItem(19, 1, QTableWidgetItem(hex(self.pe.OPTIONAL_HEADER.SizeOfImage)))
        widgets.tableWidget_data.setItem(20, 0, QTableWidgetItem('SizeOfHeaders'))
        widgets.tableWidget_data.setItem(20, 1, QTableWidgetItem(hex(self.pe.OPTIONAL_HEADER.SizeOfHeaders)))
        widgets.tableWidget_data.setItem(21, 0, QTableWidgetItem('CheckSum'))
        widgets.tableWidget_data.setItem(21, 1, QTableWidgetItem(hex(self.pe.OPTIONAL_HEADER.CheckSum)))
        widgets.tableWidget_data.setItem(22, 0, QTableWidgetItem('Subsystem'))
        widgets.tableWidget_data.setItem(22, 1, QTableWidgetItem(hex(self.pe.OPTIONAL_HEADER.Subsystem)))
        widgets.tableWidget_data.setItem(23, 0, QTableWidgetItem('DllCharacteristics'))
        widgets.tableWidget_data.setItem(23, 1, QTableWidgetItem(hex(self.pe.OPTIONAL_HEADER.DllCharacteristics)))
        widgets.tableWidget_data.setItem(24, 0, QTableWidgetItem('SizeOfStackReserve'))
        widgets.tableWidget_data.setItem(24, 1, QTableWidgetItem(hex(self.pe.OPTIONAL_HEADER.SizeOfStackReserve)))
        widgets.tableWidget_data.setItem(25, 0, QTableWidgetItem('SizeOfStackCommit'))
        widgets.tableWidget_data.setItem(25, 1, QTableWidgetItem(hex(self.pe.OPTIONAL_HEADER.SizeOfStackCommit)))
        widgets.tableWidget_data.setItem(26, 0, QTableWidgetItem('SizeOfHeapReserve'))
        widgets.tableWidget_data.setItem(26, 1, QTableWidgetItem(hex(self.pe.OPTIONAL_HEADER.SizeOfHeapReserve)))
        widgets.tableWidget_data.setItem(27, 0, QTableWidgetItem('SizeOfHeapCommit'))
        widgets.tableWidget_data.setItem(27, 1, QTableWidgetItem(hex(self.pe.OPTIONAL_HEADER.SizeOfHeapCommit)))
        widgets.tableWidget_data.setItem(28, 0, QTableWidgetItem('LoaderFlags'))
        widgets.tableWidget_data.setItem(28, 1, QTableWidgetItem(hex(self.pe.OPTIONAL_HEADER.LoaderFlags)))
        widgets.tableWidget_data.setItem(29, 0, QTableWidgetItem('NumberOfRvaAndSizes'))
        widgets.tableWidget_data.setItem(29, 1, QTableWidgetItem(hex(self.pe.OPTIONAL_HEADER.NumberOfRvaAndSizes)))

    def show_ascii(self):
        try:
            with open(self.filepath, "rb") as f:
                data = f.read()
                for i in range(0, len(data), 16):
                    line = data[i:i + 16]
                    hex_line = " ".join([f"{b:02X}" for b in line])
                    ascii_line = "".join([chr(b) if 32 <= b <= 126 else "." for b in line])
                    widgets.textBrowser.append(f"{i:08X} | {hex_line:<48} | {ascii_line}")
            # 创建一个QTextCursor对象
            widgets.cursor1 = QTextCursor(widgets.textBrowser.document())
            # 将光标移动到文本的第一行
            widgets.cursor1.movePosition(QTextCursor.Start)
            widgets.cursor1.movePosition(QTextCursor.NextBlock)
            # 将光标设置到QTextBrowser中
            widgets.textBrowser.setTextCursor(widgets.cursor1)
        except:
            print("error found in show_ascii")

    def show_reverse(self):
        try:
            # 获取代码段的起始地址和长度
            code_section = self.pe.sections[0]
            code_start = code_section.VirtualAddress
            code_end = code_start + code_section.SizeOfRawData

            # 读取代码段的二进制代码写入test.bin
            with open("test.bin", "wb") as f:
                f.write(code_section.get_data())

            # 创建Capstone反汇编器对象
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

            # 反汇编二进制代码
            with open("test.bin", "rb") as f:
                binary_code = f.read()
            for instr in md.disasm(binary_code, code_start):
                re_data = f'{hex(instr.address)}\t{instr.mnemonic}\t{instr.op_str}'
                widgets.textBrowser_34.append(re_data)
                # 创建一个QTextCursor对象
                widgets.cursor2 = QTextCursor(widgets.textBrowser_34.document())
                # 将光标移动到文本的第一行
                widgets.cursor2.movePosition(QTextCursor.Start)
                widgets.cursor2.movePosition(QTextCursor.NextBlock)
                # 将光标设置到QTextBrowser中
                widgets.textBrowser_34.setTextCursor(widgets.cursor2)
        except:
            print("error found in show_reverse")

    def show_sections_combobox(self):
        try:
            for sd in self.section_data:
                widgets.comboBox_6.addItem(sd)
        except:
            print("error found in show_sections_combobox")

    def on_comboBox_selected(self):
        try:
            cbx = self.sender()
            cbxName = cbx.objectName()
            print(cbxName)
            if cbxName == "comboBox_6":
                # 获取当前选中项的文本
                selected_text = widgets.comboBox_6.currentText()
                self.section_name = selected_text
                self.show_secion_table()
            if cbxName == "comboBox_2":
                selected_text = widgets.comboBox_2.currentText()
                print(selected_text)
                if selected_text == "if else":
                    widgets.stackedWidget_code.setCurrentWidget(widgets.ifelse_code)
                    widgets.stackedWidget_graph.setCurrentWidget(widgets.ifelse_graph)
                if selected_text == "for":
                    widgets.stackedWidget_code.setCurrentWidget(widgets.for_code)
                    widgets.stackedWidget_graph.setCurrentWidget(widgets.for_graph)
                if selected_text == "switch":
                    widgets.stackedWidget_code.setCurrentWidget(widgets.switch_code)
                    widgets.stackedWidget_graph.setCurrentWidget(widgets.switch_graph)
                if selected_text == "while":
                    widgets.stackedWidget_code.setCurrentWidget(widgets.while_code)
                    widgets.stackedWidget_graph.setCurrentWidget(widgets.while_graph)
        except:
            print("error found in on_comboBox_selected")

    def show_secion_table(self):
        try:
            for section in self.pe.sections:
                if section.Name.decode().rstrip('\x00') == self.section_name:
                    item1 = widgets.tableWidget_2.item(0, 1)
                    item1.setText(QCoreApplication.translate("MainWindow", section.Name.decode().rstrip('\x00'), None));
                    item2 = widgets.tableWidget_2.item(1, 1)
                    item2.setText(QCoreApplication.translate("MainWindow", hex(section.Misc_VirtualSize), None));
                    item3 = widgets.tableWidget_2.item(2, 1)
                    item3.setText(QCoreApplication.translate("MainWindow", hex(section.VirtualAddress), None));
                    item4 = widgets.tableWidget_2.item(3, 1)
                    item4.setText(QCoreApplication.translate("MainWindow", hex(section.SizeOfRawData), None));
                    item5 = widgets.tableWidget_2.item(4, 1)
                    item5.setText(QCoreApplication.translate("MainWindow", hex(section.PointerToRawData), None));
                    item6 = widgets.tableWidget_2.item(5, 1)
                    item6.setText(QCoreApplication.translate("MainWindow", str(section.PointerToRelocations), None));
                    item7 = widgets.tableWidget_2.item(6, 1)
                    item7.setText(QCoreApplication.translate("MainWindow", str(section.PointerToLinenumbers), None));
                    item8 = widgets.tableWidget_2.item(7, 1)
                    item8.setText(QCoreApplication.translate("MainWindow", str(section.NumberOfRelocations), None));
                    item9 = widgets.tableWidget_2.item(8, 1)
                    item9.setText(QCoreApplication.translate("MainWindow", str(section.NumberOfLinenumbers), None));
                    item10 = widgets.tableWidget_2.item(9, 1)
                    item10.setText(QCoreApplication.translate("MainWindow", hex(section.Characteristics), None));
        except:
            print("error found in show_secion_table")

    def show_data_direction(self):
        try:
            for i, entry in enumerate(self.pe.OPTIONAL_HEADER.DATA_DIRECTORY):
                widgets.tableWidget_4.setItem(i, 1, QTableWidgetItem(hex(entry.VirtualAddress)))
                widgets.tableWidget_4.setItem(i, 2, QTableWidgetItem(hex(entry.Size)))
            # item1 = widgets.tableWidget_4.item(i, 1)
            # item1.setText(QCoreApplication.translate("MainWindow", hex(entry.VirtualAddress), None));
            # item2 = widgets.tableWidget_4.item(i, 2)
            # item2.setText(QCoreApplication.translate("MainWindow", hex(entry.Size), None));
        except:
            print("error found in show_data_direction")

    def show_import_info(self):
        try:
            i = 0
            if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
                for import_dll in self.pe.DIRECTORY_ENTRY_IMPORT:
                    for import_func in import_dll.imports:
                        if i >= widgets.tableWidget.rowCount():
                            widgets.tableWidget.insertRow(i)
                        widgets.tableWidget.setItem(i, 0, QTableWidgetItem(import_dll.dll.decode().rstrip('\x00')))
                        widgets.tableWidget.setItem(i, 1, QTableWidgetItem(import_func.name.decode().rstrip('\x00')))
                        widgets.tableWidget.setItem(i, 2, QTableWidgetItem(hex(import_func.address)))
                        i = i + 1
            else:
                print("该文件没有导入表信息")
        except:
            print("error found in show_import_info")

    def show_output_info(self):
        try:
            i = 0
            if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
                for export in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if i >= widgets.tableWidget_3.rowCount():
                        widgets.tableWidget_3.insertRow(i)
                    widgets.tableWidget_3.setItem(i, 0, QTableWidgetItem(export.name.decode().rstrip('\x00')))
                    widgets.tableWidget_3.setItem(i, 1, QTableWidgetItem(hex(export.address)))
                    widgets.tableWidget_3.setItem(i, 2, QTableWidgetItem(hex(export.ordinal)))
                    i = i + 1
            else:
                print("该文件没有导入表信息")
        except:
            print("error found in show_output_info")
    # RESIZE EVENTS
    # ///////////////////////////////////////////////////////////////
    def resizeEvent(self, event):
        # Update Size Grips
        UIFunctions.resize_grips(self)

    # MOUSE CLICK EVENTS
    # ///////////////////////////////////////////////////////////////
    def mousePressEvent(self, event):
        # SET DRAG POS WINDOW
        self.dragPos = event.globalPos()

        # PRINT MOUSE EVENTS
        if event.buttons() == Qt.LeftButton:
            print('Mouse click: LEFT CLICK')
        if event.buttons() == Qt.RightButton:
            print('Mouse click: RIGHT CLICK')

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setWindowIcon(QIcon("icon.ico"))
    window = MainWindow()
    sys.exit(app.exec_())
