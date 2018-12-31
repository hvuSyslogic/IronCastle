using System;
using BouncyCastle.Core.Port.java.text;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.text;
using org.bouncycastle.util;

namespace org.bouncycastle.asn1
{

		
	/// <summary>
	/// Base class representing the ASN.1 GeneralizedTime type.
	/// <para>
	/// The main difference between these and UTC time is a 4 digit year.
	/// </para>
	/// <para>
	/// One second resolution date+time on UTC timezone (Z)
	/// with 4 digit year (valid from 0001 to 9999).
	/// </para>
	/// </para><para>
	/// Timestamp format is:  yyyymmddHHMMSS'Z'
	/// </para><para>
	/// <h2>X.690</h2>
	/// This is what is called "restricted string",
	/// and it uses ASCII characters to encode digits and supplemental data.
	/// 
	/// <h3>11: Restrictions on BER employed by both CER and DER</h3>
	/// <h4>11.7 GeneralizedTime </h4>
	/// <para>
	/// <b>11.7.1</b> The encoding shall terminate with a "Z",
	/// as described in the ITU-T Rec. X.680 | ISO/IEC 8824-1 clause on
	/// GeneralizedTime.
	/// </para>
	/// </para><para>
	/// <b>11.7.2</b> The seconds element shall always be present.
	/// </p>
	/// <para>
	/// <b>11.7.3</b> The fractional-seconds elements, if present,
	/// shall omit all trailing zeros; if the elements correspond to 0,
	/// they shall be wholly omitted, and the decimal point element also
	/// shall be omitted.
	/// </para>
	/// </summary>
	public class ASN1GeneralizedTime : ASN1Primitive
	{
		protected internal byte[] time;

		/// <summary>
		/// return a generalized time from the passed in object
		/// </summary>
		/// <param name="obj"> an ASN1GeneralizedTime or an object that can be converted into one. </param>
		/// <returns> an ASN1GeneralizedTime instance, or null. </returns>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		public static ASN1GeneralizedTime getInstance(object obj)
		{
			if (obj == null || obj is ASN1GeneralizedTime)
			{
				return (ASN1GeneralizedTime)obj;
			}

			if (obj is byte[])
			{
				try
				{
					return (ASN1GeneralizedTime)fromByteArray((byte[])obj);
				}
				catch (Exception e)
				{
					throw new IllegalArgumentException("encoding error in getInstance: " + e.ToString());
				}
			}

			throw new IllegalArgumentException("illegal object in getInstance: " + obj.GetType().getName());
		}

		/// <summary>
		/// return a Generalized Time object from a tagged object.
		/// </summary>
		/// <param name="obj">      the tagged object holding the object we want </param>
		/// <param name="explicit"> true if the object is meant to be explicitly
		///                 tagged false otherwise. </param>
		/// <returns> an ASN1GeneralizedTime instance. </returns>
		/// <exception cref="IllegalArgumentException"> if the tagged object cannot
		/// be converted. </exception>
		public static ASN1GeneralizedTime getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			ASN1Primitive o = obj.getObject();

			if (@explicit || o is ASN1GeneralizedTime)
			{
				return getInstance(o);
			}
			else
			{
				return new ASN1GeneralizedTime(((ASN1OctetString)o).getOctets());
			}
		}

		/// <summary>
		/// The correct format for this is YYYYMMDDHHMMSS[.f]Z, or without the Z
		/// for local time, or Z+-HHMM on the end, for difference between local
		/// time and UTC time. The fractional second amount f must consist of at
		/// least one number with trailing zeroes removed.
		/// </summary>
		/// <param name="time"> the time string. </param>
		/// <exception cref="IllegalArgumentException"> if String is an illegal format. </exception>
		public ASN1GeneralizedTime(string time)
		{
			this.time = Strings.toByteArray(time);
			try
			{
				this.getDate();
			}
			catch (ParseException e)
			{
				throw new IllegalArgumentException("invalid date string: " + e.Message);
			}
		}

		/// <summary>
		/// Base constructor from a java.util.date object
		/// </summary>
		/// <param name="time"> a date object representing the time of interest. </param>
		public ASN1GeneralizedTime(DateTime time)
		{
			SimpleDateFormat dateF = new SimpleDateFormat("yyyyMMddHHmmss'Z'", DateUtil.EN_Locale);

			dateF.setTimeZone(new SimpleTimeZone(0, "Z"));

			this.time = Strings.toByteArray(dateF.format(time));
		}

		/// <summary>
		/// Base constructor from a java.util.date and Locale - you may need to use this if the default locale
		/// doesn't use a Gregorian calender so that the GeneralizedTime produced is compatible with other ASN.1 implementations.
		/// </summary>
		/// <param name="time"> a date object representing the time of interest. </param>
		/// <param name="locale"> an appropriate Locale for producing an ASN.1 GeneralizedTime value. </param>
		public ASN1GeneralizedTime(DateTime time, Locale locale)
		{
			SimpleDateFormat dateF = new SimpleDateFormat("yyyyMMddHHmmss'Z'", locale);

			dateF.setTimeZone(new SimpleTimeZone(0, "Z"));

			this.time = Strings.toByteArray(dateF.format(time));
		}

		public ASN1GeneralizedTime(byte[] bytes)
		{
			this.time = bytes;
		}

		/// <summary>
		/// Return the time.
		/// </summary>
		/// <returns> The time string as it appeared in the encoded object. </returns>
		public virtual string getTimeString()
		{
			return Strings.fromByteArray(time);
		}

		/// <summary>
		/// return the time - always in the form of
		/// YYYYMMDDhhmmssGMT(+hh:mm|-hh:mm).
		/// <para>
		/// Normally in a certificate we would expect "Z" rather than "GMT",
		/// however adding the "GMT" means we can just use:
		/// <pre>
		///     dateF = new SimpleDateFormat("yyyyMMddHHmmssz");
		/// </pre>
		/// To read in the time and get a date which is compatible with our local
		/// time zone.
		/// </para>
		/// </summary>
		/// <returns> a String representation of the time. </returns>
		public virtual string getTime()
		{
			string stime = Strings.fromByteArray(time);

			//
			// standardise the format.
			//
			if (stime[stime.Length - 1] == 'Z')
			{
				return stime.Substring(0, stime.Length - 1) + "GMT+00:00";
			}
			else
			{
				int signPos = stime.Length - 5;
				char sign = stime[signPos];
				if (sign == '-' || sign == '+')
				{
					return stime.Substring(0, signPos) + "GMT"
						+ stime.Substring(signPos, 3) + ":"
						+ stime.Substring(signPos + 3);
				}
				else
				{
					signPos = stime.Length - 3;
					sign = stime[signPos];
					if (sign == '-' || sign == '+')
					{
						return stime.Substring(0, signPos) + "GMT"
							+ stime.Substring(signPos) + ":00";
					}
				}
			}
			return stime + calculateGMTOffset();
		}

		private string calculateGMTOffset()
		{
			string sign = "+";
			TimeZone timeZone = TimeZone.getDefault();
			int offset = timeZone.getRawOffset();
			if (offset < 0)
			{
				sign = "-";
				offset = -offset;
			}
			int hours = offset / (60 * 60 * 1000);
			int minutes = (offset - (hours * 60 * 60 * 1000)) / (60 * 1000);

			try
			{
				if (timeZone.useDaylightTime() && timeZone.inDaylightTime(this.getDate()))
				{
					hours += sign.Equals("+") ? 1 : -1;
				}
			}
			catch (ParseException)
			{
				// we'll do our best and ignore daylight savings
			}

			return "GMT" + sign + convert(hours) + ":" + convert(minutes);
		}

		private string convert(int time)
		{
			if (time < 10)
			{
				return "0" + time;
			}

			return Convert.ToString(time);
		}

		public virtual DateTime getDate()
		{
			SimpleDateFormat dateF;
			string stime = Strings.fromByteArray(time);
			string d = stime;

			if (stime.EndsWith("Z", StringComparison.Ordinal))
			{
				if (hasFractionalSeconds())
				{
					dateF = new SimpleDateFormat("yyyyMMddHHmmss.SSS'Z'");
				}
				else if (hasSeconds())
				{
					dateF = new SimpleDateFormat("yyyyMMddHHmmss'Z'");
				}
				else if (hasMinutes())
				{
					dateF = new SimpleDateFormat("yyyyMMddHHmm'Z'");
				}
				else
				{
					dateF = new SimpleDateFormat("yyyyMMddHH'Z'");
				}

				dateF.setTimeZone(new SimpleTimeZone(0, "Z"));
			}
			else if (stime.IndexOf('-') > 0 || stime.IndexOf('+') > 0)
			{
				d = this.getTime();
				if (hasFractionalSeconds())
				{
					dateF = new SimpleDateFormat("yyyyMMddHHmmss.SSSz");
				}
				else if (hasSeconds())
				{
					dateF = new SimpleDateFormat("yyyyMMddHHmmssz");
				}
				else if (hasMinutes())
				{
					dateF = new SimpleDateFormat("yyyyMMddHHmmz");
				}
				else
				{
					dateF = new SimpleDateFormat("yyyyMMddHHz");
				}

				dateF.setTimeZone(new SimpleTimeZone(0, "Z"));
			}
			else
			{
				if (hasFractionalSeconds())
				{
					dateF = new SimpleDateFormat("yyyyMMddHHmmss.SSS");
				}
				else if (hasSeconds())
				{
					dateF = new SimpleDateFormat("yyyyMMddHHmmss");
				}
				else if (hasMinutes())
				{
					dateF = new SimpleDateFormat("yyyyMMddHHmm");
				}
				else
				{
					dateF = new SimpleDateFormat("yyyyMMddHH");
				}

				dateF.setTimeZone(new SimpleTimeZone(0, TimeZone.getDefault().getID()));
			}

			if (hasFractionalSeconds())
			{
				// java misinterprets extra digits as being milliseconds...
				string frac = d.Substring(14);
				int index;
				for (index = 1; index < frac.Length; index++)
				{
					char ch = frac[index];
					if (!('0' <= ch && ch <= '9'))
					{
						break;
					}
				}

				if (index - 1 > 3)
				{
					frac = frac.Substring(0, 4) + frac.Substring(index);
					d = d.Substring(0, 14) + frac;
				}
				else if (index - 1 == 1)
				{
					frac = frac.Substring(0, index) + "00" + frac.Substring(index);
					d = d.Substring(0, 14) + frac;
				}
				else if (index - 1 == 2)
				{
					frac = frac.Substring(0, index) + "0" + frac.Substring(index);
					d = d.Substring(0, 14) + frac;
				}
			}

			return DateUtil.epochAdjust(dateF.parse(d));
		}

		public virtual bool hasFractionalSeconds()
		{
			for (int i = 0; i != time.Length; i++)
			{
				if (time[i] == (byte)'.')
				{
					if (i == 14)
					{
						return true;
					}
				}
			}
			return false;
		}

		public virtual bool hasSeconds()
		{
			return isDigit(12) && isDigit(13);
		}

		public virtual bool hasMinutes()
		{
			return isDigit(10) && isDigit(11);
		}

		private bool isDigit(int pos)
		{
			return time.Length > pos && time[pos] >= (byte)'0' && time[pos] <= (byte)'9';
		}

		public override bool isConstructed()
		{
			return false;
		}

		public override int encodedLength()
		{
			int length = time.Length;

			return 1 + StreamUtil.calculateBodyLength(length) + length;
		}

		public override void encode(ASN1OutputStream @out)
		{
			@out.writeEncoded(BERTags_Fields.GENERALIZED_TIME, time);
		}

		public override ASN1Primitive toDERObject()
		{
			return new DERGeneralizedTime(time);
		}

		public override bool asn1Equals(ASN1Primitive o)
		{
			if (!(o is ASN1GeneralizedTime))
			{
				return false;
			}

			return Arrays.areEqual(time, ((ASN1GeneralizedTime)o).time);
		}

		public override int GetHashCode()
		{
			return Arrays.GetHashCode(time);
		}
	}

}