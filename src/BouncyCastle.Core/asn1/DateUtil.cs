using System;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1
{

	public class DateUtil
	{
		private static long? ZERO = Convert.ToInt64(0);

		private static readonly Map localeCache = new HashMap();

		internal static Locale EN_Locale = forEN();

		private static Locale forEN()
		{
			if ("en".Equals(Locale.getDefault().getLanguage(), StringComparison.OrdinalIgnoreCase))
			{
				return Locale.getDefault();
			}

			Locale[] locales = Locale.getAvailableLocales();
			for (int i = 0; i != locales.Length; i++)
			{
				if ("en".Equals(locales[i].getLanguage(), StringComparison.OrdinalIgnoreCase))
				{
					return locales[i];
				}
			}

			return Locale.getDefault();
		}

		internal static DateTime epochAdjust(DateTime date)
		{
			Locale locale = Locale.getDefault();
			if (locale == null)
			{
				return date;
			}

			lock (localeCache)
			{
				long? adj = (long?)localeCache.get(locale);

				if (adj == null)
				{
					SimpleDateFormat dateF = new SimpleDateFormat("yyyyMMddHHmmssz");
					long v = dateF.parse("19700101000000GMT+00:00").getTime();

					if (v == 0)
					{
						adj = ZERO;
					}
					else
					{
						adj = Convert.ToInt64(v);
					}

					localeCache.put(locale, adj);
				}

				if (adj != ZERO)
				{
					return new DateTime(date.Ticks - adj.Value);
				}

				return date;
			}
		}
	}

}