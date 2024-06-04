#include "mainwindow.h"
#include "ui_mainwindow.h"
#include<QFileDialog>
#include<QMessageBox>
MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    connect(ui->pushButton,&QPushButton::clicked,[&](){
        KEY_LENG leng;
        if(ui->comboBox->currentText()=="1024")
        {
            leng=KEY_LENG::KEY_1024;
        }
        else if(ui->comboBox->currentText()=="2048")
        {
            leng=KEY_LENG::KEY_2048;
        }
        else if(ui->comboBox->currentText()=="4096")
        {
            leng=KEY_LENG::KEY_4096;
        }
        auto list=generateRSAKey(leng);
        ui->plainTextEdit->setPlainText(list.at(0));
        ui->plainTextEdit_2->setPlainText(list.at(1));
    });
    connect(ui->pushButton_2,&QPushButton::clicked,[&](){
//        QDir dir;
//        dir.mkdir("密钥");
        if(ui->plainTextEdit->toPlainText().isEmpty())
        {
            return ;
        }
        //QString fileName = QFileDialog::getSaveFileName(this, "保存私钥文件", "./密钥/私钥.pem", "密钥文件(*.pem)");
        QString fileName = QFileDialog::getSaveFileName(this, "保存私钥文件", "./私钥.pem", "密钥文件(*.pem);;任意文本文件(*.*)");
        //QFile file("./rsa_private_key.pem");
        if(fileName.isEmpty())
        {
            return ;
        }
        QFile file(fileName);
        if(file.open(QIODevice::WriteOnly))
        {
            QString data=ui->plainTextEdit->toPlainText();
            file.write(data.toUtf8());
            file.close();
            QMessageBox::information(this, "提示信息", "保存成功！！");
        }
    });
    connect(ui->pushButton_3,&QPushButton::clicked,[&](){
//        QDir dir;
//        dir.mkdir("密钥");
        if(ui->plainTextEdit_2->toPlainText().isEmpty())
        {
            return ;
        }
        //QString fileName = QFileDialog::getSaveFileName(this, "保存私钥文件", "./密钥/公钥.pem", "密钥文件(*.pem)");
        QString fileName = QFileDialog::getSaveFileName(this, "保存私钥文件", "./公钥.pem", "密钥文件(*.pem);;任意文本文件(*.*)");
        //QFile file("./rsa_private_key.pem");
        if(fileName.isEmpty())
        {
            return ;
        }
        QFile file(fileName);
        if(file.open(QIODevice::WriteOnly))
        {
            QString data=ui->plainTextEdit_2->toPlainText();
            file.write(data.toUtf8());
            file.close();
            QMessageBox::information(this, "提示信息", "保存成功！！");
        }
    });

    connect(ui->pushButton_4,&QPushButton::clicked,[&](){

        QString str=QFileDialog::getOpenFileName(this,"读取私钥文件", "./密钥/", "密钥文件(*.pem);;任意文本文件(*.*)");
        if(str.isEmpty())
        {
            return;
        }
        QFile file(str);
        if(file.open(QIODevice::ReadOnly|QIODevice::Text))
        {
            QString pub=file.readAll();
            ui->plainTextEdit->setPlainText(pub);
            file.close();
        }
    });

    connect(ui->pushButton_5,&QPushButton::clicked,[&](){

        QString str=QFileDialog::getOpenFileName(this,"读取公钥文件", "./密钥/", "密钥文件(*.pem);;任意文本文件(*.*)");
        if(str.isEmpty())
        {
            return;
        }
        QFile file(str);
        if(file.open(QIODevice::ReadOnly|QIODevice::Text))
        {
            QString pub=file.readAll();
            ui->plainTextEdit_2->setPlainText(pub);
            file.close();
        }
    });

    connect(ui->pushButton_6,&QPushButton::clicked,[&](){

        if (ui->plainTextEdit_2->toPlainText().isEmpty() || ui->plainTextEdit_3->toPlainText().isEmpty())
        {
            return;
        }
        ui->plainTextEdit_4->setPlainText(rsaPubEncrypt(ui->plainTextEdit_3->toPlainText(),ui->plainTextEdit_2->toPlainText()));

    });

    connect(ui->pushButton_7,&QPushButton::clicked,[&](){

        if (ui->plainTextEdit->toPlainText().isEmpty() || ui->plainTextEdit_4->toPlainText().isEmpty())
        {
            return;
        }
        ui->plainTextEdit_3->setPlainText(rsaPriDecrypt(ui->plainTextEdit_4->toPlainText(),ui->plainTextEdit->toPlainText()));

    });

    connect(ui->pushButton_8,&QPushButton::clicked,[&](){

        if (ui->plainTextEdit->toPlainText().isEmpty() || ui->plainTextEdit_3->toPlainText().isEmpty())
        {
            return;
        }
        ui->plainTextEdit_4->setPlainText(rsaPriEncrypt(ui->plainTextEdit_3->toPlainText(),ui->plainTextEdit->toPlainText()));

    });

    connect(ui->pushButton_9,&QPushButton::clicked,[&](){

        if (ui->plainTextEdit_2->toPlainText().isEmpty() || ui->plainTextEdit_4->toPlainText().isEmpty())
        {
            return;
        }
        ui->plainTextEdit_3->setPlainText(rsaPubDecrypt(ui->plainTextEdit_4->toPlainText(),ui->plainTextEdit_2->toPlainText()));

    });
    connect(ui->pushButton_10,&QPushButton::clicked,[&](){

        if (ui->plainTextEdit->toPlainText().isEmpty())
        {
            return;
        }
        ui->plainTextEdit_2->setPlainText(generateRSAPUBKey(ui->plainTextEdit->toPlainText()));

    });
}


MainWindow::~MainWindow()
{
    delete ui;
}

