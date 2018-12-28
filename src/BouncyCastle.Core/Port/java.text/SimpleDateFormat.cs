using System;

namespace BouncyCastle.Core.Port.java.text
{
    public abstract class DateFormat
    {
        public virtual string format(DateTime date)
        {
            throw new NotImplementedException();
        }
    }

    public class SimpleDateFormat:DateFormat
    {

        public SimpleDateFormat(string v)
        {
        }

        public SimpleDateFormat(string v, Locale locale) : this(v)
        {
        }

        public void setTimeZone(SimpleTimeZone p0)
        {
            throw new NotImplementedException();
        }

        public DateTime parse(string s)
        {
            throw new NotImplementedException();
        }

        public override string format(DateTime time)
        {
            throw new NotImplementedException();
        }
    }

    public class DateTime
    {
        public DateTime(long l)
        {
            throw new NotImplementedException();
        }

        public long getTime()
        {
            throw new System.NotImplementedException();
        }

        public long ticks { get; set; }
    }
}
