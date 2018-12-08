using System;

namespace org.bouncycastle.asn1.test
{

	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class LocaleTest : SimpleTest
	{
		public override string getName()
		{
			return "LocaleTest";
		}

		private void doTestLocale(Locale l)
		{
			long time = 1538063166000L;
			string timeString = "180927154606GMT+00:00";
			string longTimeString = "20180927154606Z";

			Locale.setDefault(l);

			isTrue(time == (new DERUTCTime(timeString)).getAdjustedDate().Ticks);
			isTrue(time == (new DERGeneralizedTime(longTimeString)).getDate().Ticks);

			isTrue(time == (new DERUTCTime(new DateTime(time))).getAdjustedDate().Ticks);
			isTrue(time == (new DERGeneralizedTime(new DateTime(time))).getDate().Ticks);

			DateTime d = DateTime.Now;

			isTrue((d.Ticks - (d.Ticks % 1000)) == (new DERUTCTime(d)).getAdjustedDate().Ticks);
			isTrue((d.Ticks - (d.Ticks % 1000)) == (new DERGeneralizedTime(d)).getDate().Ticks);
		}

		public override void performTest()
		{
			Locale defLocale = Locale.getDefault();

			Locale[] list = DateFormat.getAvailableLocales();
			 foreach (Locale l in list)
			 {
				 doTestLocale(l);
			 }

			 Locale.setDefault(defLocale);
		}

		public static void Main(string[] args)
		{
			runTest(new LocaleTest());
		}
	}

}