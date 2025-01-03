using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.IO;

namespace WindowsFormsApp1
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }
        static UdpClient udp;
        static IPEndPoint sep;
        static string serverip = "172.18.11.200";
        IPEndPoint rep = new IPEndPoint(IPAddress.Parse(serverip), 0);
        Form2[] friends = new Form2[10];
        public static string username = "";
        public static void sndmsg(string ip,string msg)
        {
            DESCryptoServiceProvider des = new DESCryptoServiceProvider();
            byte[] msgBytes = Encoding.Unicode.GetBytes(msg);

            // 使用 DES 加密
            MemoryStream ms = new MemoryStream();
            CryptoStream cs = new CryptoStream(ms, des.CreateEncryptor(), CryptoStreamMode.Write);
            cs.Write(msgBytes, 0, msgBytes.Length);
            cs.FlushFinalBlock();
            byte[] cipher = ms.ToArray();

            // 轉換為 Base64 字串
            string finalMsg = Convert.ToBase64String(cipher) + ":" +
                            Convert.ToBase64String(des.Key) + ":" +
                            Convert.ToBase64String(des.IV);

            sep = new IPEndPoint(IPAddress.Parse(ip), 6606);
            byte[] data = Encoding.ASCII.GetBytes(finalMsg);
            udp.Send(data, data.Length, sep);
        }
        private void button1_Click(object sender, EventArgs e)
        {
            username = textBox1.Text;
            string password = textBox2.Text;
            if(username.Replace(" ",string.Empty) == null || username.Replace(" ", string.Empty) == "" || username.Replace(" ",string.Empty).Length < 8)
            {
                MessageBox.Show("帳號不可為空 且不可低於8碼"); return;
            }
            if(password.Replace(" ", "") == null || password.Replace(" ", "") == "")
            {
                MessageBox.Show("密碼不可為空"); return;
            }
            if (udp == null)
            {
                udp = new UdpClient(3000);
                timer1.Enabled = true;
                sndmsg(serverip, "login:" + username + ":" + password);
                button1.Visible = false;
                button2.Visible = true;
            }
            else
            {
                MessageBox.Show("You are already login,You must be logout first!!");
            }
        }

        private void timer1_Tick(object sender, EventArgs e)
        {
            if (udp.Available > 0)
            {
                DESCryptoServiceProvider des = new DESCryptoServiceProvider();
                byte[] buffer = udp.Receive(ref rep);
                string rawdata = Encoding.ASCII.GetString(buffer);
                string[] parts = rawdata.Split(':');

                // 解密使用 DES
                des.Key = Convert.FromBase64String(parts[1]);
                des.IV = Convert.FromBase64String(parts[2]);
                byte[] encryptedData = Convert.FromBase64String(parts[0]);

                MemoryStream ms = new MemoryStream(encryptedData);
                CryptoStream cs = new CryptoStream(ms, des.CreateDecryptor(), CryptoStreamMode.Read);
                StreamReader sr = new StreamReader(cs, Encoding.Unicode);
                rawdata = sr.ReadToEnd();

                string[] token = rawdata.Split(':');
                switch (token[0])
                {
                    case "loginMsg":
                        if (username != token[1])
                        {
                            listBox1.Items.Add(token[1] + ":" + token[2]);
                        }
                        break;
                    case "logoutMsg":
                        listBox1.Items.Remove(token[1] + ":" + token[2]);
                        break;
                    case "message":
                        string friendname = token[1];
                        string msg = token[2];
                        bool talking = false;

                        for (int i = 0; i < friends.Length; i++)
                        {
                            if (friendname == (string)friends[i].Text)
                            {
                                talking = true;
                                friends[i].textBox2.Text += msg + Environment.NewLine + Environment.NewLine;
                                friends[i].Select();
                            }
                        }
                        if (!talking)
                        {
                            int i = 0;
                            while (friends[i].Tag != null) i++;
                            friends[i] = new Form2();
                            friends[i].Tag = serverip;
                            friends[i].Text = friendname;
                            friends[i].textBox2.Text += msg + Environment.NewLine + Environment.NewLine;
                            friends[i].Show();
                        }
                        break;
                    case "success":
                        MessageBox.Show(token[1]);
                        break;
                    case "error":
                        timer1.Enabled = false;
                        udp.Close();
                        udp = null;
                        listBox1.Items.Clear();
                        button2.Visible = false;
                        button1.Visible = true;
                        MessageBox.Show(token[1]);
                        break;
                }
            }
        }

        private void Form1_FormClosing(object sender, FormClosingEventArgs e)
        {
            if (udp != null)
                sndmsg(serverip, "logout:" + username);
        }

        private void button2_Click(object sender, EventArgs e)
        {
            if (udp != null)
            {
                sndmsg(serverip, "logout:" + username);
                timer1.Enabled = false;
                udp.Close();
                udp = null;
                listBox1.Items.Clear();
                button2.Visible = false;
                button1.Visible = true;
            }
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            for(int i = 0; i < friends.Length; i++)
            {
                friends[i] = new Form2();
            }
        }

        private void listBox1_DoubleClick(object sender, EventArgs e)
        {
            bool talking = false;
            string friendname = listBox1.SelectedItem.ToString().Split(':')[0];
            string friendip = listBox1.SelectedItem.ToString().Split(':')[1];
            for(int i = 0; i < friends.Length; i++)
            {
                if(friendname == (string)friends[i].Text)
                {
                    talking = true;
                    friends[i].Select();
                }
            }
            if (!talking)
            {
                int i = 0;
                while (friends[i].Tag != null) i++;
                friends[i] = new Form2();
                friends[i].Tag = serverip;
                friends[i].Text = friendname;
                friends[i].Show();
            }
        }

        private void button3_Click(object sender, EventArgs e)
        {
            if (textBox2.Text == null || textBox2.Text.Replace(" ",string.Empty) == "" || textBox1.Text == null || textBox1.Text.Replace(" ",string.Empty) == "" || textBox1.Text.Length < 8)
            {
                MessageBox.Show("帳號 / 密碼不可為空,帳號須超過 8 碼");
                return;
            }
            if (udp == null) { 
                udp = new UdpClient(3000);
                timer1.Enabled = true;
                HMACMD5 md5 = new HMACMD5();
                md5.Key = Encoding.Unicode.GetBytes(textBox1.Text.Substring(0,8));
                sndmsg(serverip,"register:"+textBox1.Text+":"+BitConverter.ToString(md5.ComputeHash(Encoding.Unicode.GetBytes(textBox2.Text))).Replace("-",string.Empty).ToUpper());
            }
        }
    }
}
