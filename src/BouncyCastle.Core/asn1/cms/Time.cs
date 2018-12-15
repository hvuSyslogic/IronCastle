using BouncyCastle.Core.Port.java.text;
using org.bouncycastle.Port;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.text;

namespace org.bouncycastle.asn1.cms
{


	/// <summary>
	/// <a href="http://tools.ietf.org/html/rfc5652#section-11.3">RFC 5652</a>:
	/// Dual-mode timestamp format producing either UTCTIme or GeneralizedTime.
	/// <para>
	/// <pre>
	/// Time ::= CHOICE {
	///     utcTime        UTCTime,
	///     generalTime    GeneralizedTime }
	/// </pre>
	/// </para>
	/// <para>
	/// This has a constructor using java.util.Date for input which generates
	/// a <seealso cref="org.bouncycastle.asn1.DERUTCTime DERUTCTime"/> object if the
	/// supplied datetime is in range 1950-01-01-00:00:00 UTC until 2049-12-31-23:59:60 UTC.
	/// If the datetime value is outside that range, the generated object will be
	/// <seealso cref="org.bouncycastle.asn1.DERGeneralizedTime DERGeneralizedTime"/>.
	/// </para>
	/// </summary>
	public class Time : ASN1Object, ASN1Choice
	{
		internal ASN1Primitive time;

		public static Time getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(obj.getObject());
		}

		/// @deprecated use getInstance() 
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

		/// <summary>
		/// Return a Time object from the given object.
		/// <para>
		/// Accepted inputs:
		/// <ul>
		/// <li> null &rarr; null
		/// <li> <seealso cref="Time"/> object
		/// <li> <seealso cref="org.bouncycastle.asn1.DERUTCTime DERUTCTime"/> object
		/// <li> <seealso cref="org.bouncycastle.asn1.DERGeneralizedTime DERGeneralizedTime"/> object
		/// </ul>
		/// 
		/// </para>
		/// </summary>
		/// <param name="obj"> the object we want converted. </param>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
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

		/// <summary>
		/// Get the date+tine as a String in full form century format.
		/// </summary>
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

		/// <summary>
		/// Get java.util.Date version of date+time.
		/// </summary>
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
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			return time;
		}
	}

}