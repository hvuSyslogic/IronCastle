using System;

namespace BouncyCastle.Core.Port.java.io
{
    public class Reader
    {

    }

    public class BufferedReader : Reader
    {
        public BufferedReader(Reader inputStreamReader)
        {
            throw new NotImplementedException();
        }

        public string readLine()
        {
            throw new NotImplementedException();
        }
    }

    public class Writer
    {

    }

    public class BufferedWriter : Writer
    {

        public BufferedWriter(Writer @out)
        {
        }

        public void newLine()
        {
            throw new System.NotImplementedException();
        }

        public void write(string getName)
        {
            throw new System.NotImplementedException();
        }

        public void write(char[] buf, int v, int index)
        {
            throw new NotImplementedException();
        }
    }

}
