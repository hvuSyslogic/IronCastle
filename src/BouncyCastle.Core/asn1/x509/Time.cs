using System;
using org.bouncycastle.Port;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.text;

namespace org.bouncycastle.asn1.x509
{


	public class Time : ASN1Object, ASN1Choice
	{
		internal ASN1Primitive time;

		public static Time getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(obj.getObject()); // must be explicitly tagged
		}

		public Time(ASN1Primitive time)
		{
			if (!(time is ASN1UTCTime) && !(time is ASN1GeneralizedTime))
			{
				throw new IllegalArgumentException("unknown object passed to Time");
			}

			this.time = time;
		}

		/// <summary>
		/// Creates a time object from a given date - if the date is between 1950
		/// and 2049 a UTCTime object is generated, otherwise a GeneralizedTime
		/// is used.
		/// </summary>
		/// <param name="time"> a date object representing the time of interest. </param>
		public Time(DateTime time)
		{
			SimpleTimeZone tz = new SimpleTimeZone(0, "Z");
			SimpleDateFormat dateF = new SimpleDateFormat("yyyyMMddHHmmss");

			dateF.setTimeZone(tz);

			string d = dateF.format(time) + "Z";
			int year = int.Parse(d.Substring(0, 4));

			if (year < 1950 || year > 2049)
			{
				this.time = new DERGeneralizedTime(d);
			}
			else
			{
				this.time = new DERUTCTime(d.Substring(2));
			}
		}

		/// <summary>
		/// Creates a time object from a given date and locale - if the date is between 1950
		/// and 2049 a UTCTime object is generated, otherwise a GeneralizedTime
		/// is used. You may need to use this constructor if the default locale
		/// doesn't use a Gregorian calender so that the GeneralizedTime produced is compatible with other ASN.1 implementations.
		/// </summary>
		/// <param name="time"> a date object representing the time of interest. </param>
		/// <param name="locale"> an appropriate Locale for producing an ASN.1 GeneralizedTime value. </param>
		public Time(DateTime time, Locale locale)
		{
			SimpleTimeZone tz = new SimpleTimeZone(0, "Z");
			SimpleDateFormat dateF = new SimpleDateFormat("yyyyMMddHHmmss", locale);

			dateF.setTimeZone(tz);

			string d = dateF.format(time) + "Z";
			int year = int.Parse(d.Substring(0, 4));

			if (year < 1950 || year > 2049)
			{
				this.time = new DERGeneralizedTime(d);
			}
			else
			{
				this.time = new DERUTCTime(d.Substring(2));
			}
		}

		public static Time getInstance(object obj)
		{
			if (obj == null || obj is Time)
			{
				return (Time)obj;
			}
			else if (obj is ASN1UTCTime)
			{
				return new Time((ASN1UTCTime)obj);
			}
			else if (obj is ASN1GeneralizedTime)
			{
				return new Time((ASN1GeneralizedTime)obj);
			}

			throw new IllegalArgumentException("unknown object in factory: " + obj.GetType().getName());
		}

		public virtual string getTime()
		{
			if (time is ASN1UTCTime)
			{
				return ((ASN1UTCTime)time).getAdjustedTime();
			}
			else
			{
				return ((ASN1GeneralizedTime)time).getTime();
			}
		}

		public virtual DateTime getDate()
		{
			try
			{
				if (time is ASN1UTCTime)
				{
					return ((ASN1UTCTime)time).getAdjustedDate();
				}
				else
				{
					return ((ASN1GeneralizedTime)time).getDate();
				}
			}
			catch (ParseException e)
			{ // this should never happen
				throw new IllegalStateException("invalid date string: " + e.Message);
			}
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// <pre>
		/// Time ::= CHOICE {
		///             utcTime        UTCTime,
		///             generalTime    GeneralizedTime }
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			return time;
		}

		public override string ToString()
		{
			return getTime();
		}
	}

}