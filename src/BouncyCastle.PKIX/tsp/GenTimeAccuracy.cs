using System;

namespace org.bouncycastle.tsp
{
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using Accuracy = org.bouncycastle.asn1.tsp.Accuracy;

	public class GenTimeAccuracy
	{
		private Accuracy accuracy;

		public GenTimeAccuracy(Accuracy accuracy)
		{
			this.accuracy = accuracy;
		}

		public virtual int getSeconds()
		{
			return getTimeComponent(accuracy.getSeconds());
		}

		public virtual int getMillis()
		{
			return getTimeComponent(accuracy.getMillis());
		}

		public virtual int getMicros()
		{
			return getTimeComponent(accuracy.getMicros());
		}

		private int getTimeComponent(ASN1Integer time)
		{
			if (time != null)
			{
				return time.getValue().intValue();
			}

			return 0;
		}

		public override string ToString()
		{ // digits
			return getSeconds() + "." + format(getMillis()) + format(getMicros());
		}

		private string format(int v)
		{
			if (v < 10)
			{
				return "00" + v;
			}

			if (v < 100)
			{
				return "0" + v;
			}

			return Convert.ToString(v);
		}
	}

}