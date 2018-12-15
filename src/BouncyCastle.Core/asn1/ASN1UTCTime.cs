using System;
using BouncyCastle.Core.Port.java.text;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.text;
using DateTime = BouncyCastle.Core.Port.java.text.DateTime;

namespace org.bouncycastle.asn1
{

	using Arrays = org.bouncycastle.util.Arrays;
	using Strings = org.bouncycastle.util.Strings;

	/// <summary>
	/// - * UTC time object.
	/// Internal facade of <seealso cref="ASN1UTCTime"/>.
	/// <para>
	/// This datatype is valid only from 1950-01-01 00:00:00 UTC until 2049-12-31 23:59:59 UTC.
	/// </para>
	/// <hr>
	/// <para><b>X.690</b></para>
	/// <para><b>11: Restrictions on BER employed by both CER and DER</b></para>
	/// <para><b>11.8 UTCTime </b></para>
	/// <b>11.8.1</b> The encoding shall terminate with "Z",
	/// as described in the ITU-T X.680 | ISO/IEC 8824-1 clause on UTCTime.
	/// <para>
	/// <b>11.8.2</b> The seconds element shall always be present.
	/// </para>
	/// <para>
	/// <b>11.8.3</b> Midnight (GMT) shall be represented in the form:
	/// <blockquote>
	/// "YYMMDD000000Z"
	/// </blockquote>
	/// where "YYMMDD" represents the day following the midnight in question.
	/// </para>
	/// </summary>
	public class ASN1UTCTime : ASN1Primitive
	{
		private byte[] time;

		/// <summary>
		/// Return an UTC Time from the passed in object.
		/// </summary>
		/// <param name="obj"> an ASN1UTCTime or an object that can be converted into one. </param>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		/// <returns> an ASN1UTCTime instance, or null. </returns>
		public static ASN1UTCTime getInstance(object obj)
		{
			if (obj == null || obj is ASN1UTCTime)
			{
				return (ASN1UTCTime)obj;
			}

			if (obj is byte[])
			{
				try
				{
					return (ASN1UTCTime)fromByteArray((byte[])obj);
				}
				catch (Exception e)
				{
					throw new IllegalArgumentException("encoding error in getInstance: " + e.ToString());
				}
			}

			throw new IllegalArgumentException("illegal object in getInstance: " + obj.GetType().getName());
		}

		/// <summary>
		/// Return an UTC Time from a tagged object.
		/// </summary>
		/// <param name="obj"> the tagged object holding the object we want </param>
		/// <param name="explicit"> true if the object is meant to be explicitly
		///              tagged false otherwise. </param>
		/// <exception cref="IllegalArgumentException"> if the tagged object cannot
		///               be converted. </exception>
		/// <returns> an ASN1UTCTime instance, or null. </returns>
		public static ASN1UTCTime getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			ASN1Object o = obj.getObject();

			if (@explicit || o is ASN1UTCTime)
			{
				return getInstance(o);
			}
			else
			{
				return new ASN1UTCTime(((ASN1OctetString)o).getOctets());
			}
		}

		/// <summary>
		/// The correct format for this is YYMMDDHHMMSSZ (it used to be that seconds were
		/// never encoded. When you're creating one of these objects from scratch, that's
		/// what you want to use, otherwise we'll try to deal with whatever gets read from
		/// the input stream... (this is why the input format is different from the getTime()
		/// method output).
		/// <para>
		/// 
		/// </para>
		/// </summary>
		/// <param name="time"> the time string. </param>
		public ASN1UTCTime(string time)
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
		/// Base constructor from a java.util.date object </summary>
		/// <param name="time"> the Date to build the time from. </param>
		public ASN1UTCTime(DateTime time)
		{
			SimpleDateFormat dateF = new SimpleDateFormat("yyMMddHHmmss'Z'", DateUtil.EN_Locale);

			dateF.setTimeZone(new SimpleTimeZone(0,"Z"));

			this.time = Strings.toByteArray(dateF.format(time));
		}

		/// <summary>
		/// Base constructor from a java.util.date and Locale - you may need to use this if the default locale
		/// doesn't use a Gregorian calender so that the GeneralizedTime produced is compatible with other ASN.1 implementations.
		/// </summary>
		/// <param name="time"> a date object representing the time of interest. </param>
		/// <param name="locale"> an appropriate Locale for producing an ASN.1 UTCTime value. </param>
		public ASN1UTCTime(DateTime time, Locale locale)
		{
			SimpleDateFormat dateF = new SimpleDateFormat("yyMMddHHmmss'Z'", locale);

			dateF.setTimeZone(new SimpleTimeZone(0,"Z"));

			this.time = Strings.toByteArray(dateF.format(time));
		}

		public ASN1UTCTime(byte[] time)
		{
			this.time = time;
		}

		/// <summary>
		/// Return the time as a date based on whatever a 2 digit year will return. For
		/// standardised processing use getAdjustedDate().
		/// </summary>
		/// <returns> the resulting date </returns>
		/// <exception cref="ParseException"> if the date string cannot be parsed. </exception>
		public virtual DateTime getDate()
		{
			SimpleDateFormat dateF = new SimpleDateFormat("yyMMddHHmmssz");

			return DateUtil.epochAdjust(dateF.parse(getTime()));
		}

		/// <summary>
		/// Return the time as an adjusted date
		/// in the range of 1950 - 2049.
		/// </summary>
		/// <returns> a date in the range of 1950 to 2049. </returns>
		/// <exception cref="ParseException"> if the date string cannot be parsed. </exception>
		public virtual DateTime getAdjustedDate()
		{
			SimpleDateFormat dateF = new SimpleDateFormat("yyyyMMddHHmmssz");

			dateF.setTimeZone(new SimpleTimeZone(0,"Z"));

			return DateUtil.epochAdjust(dateF.parse(getAdjustedTime()));
		}

		/// <summary>
		/// Return the time - always in the form of
		///  YYMMDDhhmmssGMT(+hh:mm|-hh:mm).
		/// <para>
		/// Normally in a certificate we would expect "Z" rather than "GMT",
		/// however adding the "GMT" means we can just use:
		/// <pre>
		///     dateF = new SimpleDateFormat("yyMMddHHmmssz");
		/// </pre>
		/// To read in the time and get a date which is compatible with our local
		/// time zone.
		/// </para>
		/// <para>
		/// <b>Note:</b> In some cases, due to the local date processing, this
		/// may lead to unexpected results. If you want to stick the normal
		/// convention of 1950 to 2049 use the getAdjustedTime() method.
		/// </para>
		/// </summary>
		public virtual string getTime()
		{
			string stime = Strings.fromByteArray(time);

			//
			// standardise the format.
			//
			if (stime.IndexOf('-') < 0 && stime.IndexOf('+') < 0)
			{
				if (stime.Length == 11)
				{
					return stime.Substring(0, 10) + "00GMT+00:00";
				}
				else
				{
					return stime.Substring(0, 12) + "GMT+00:00";
				}
			}
			else
			{
				int index = stime.IndexOf('-');
				if (index < 0)
				{
					index = stime.IndexOf('+');
				}
				string d = stime;

				if (index == stime.Length - 3)
				{
					d += "00";
				}

				if (index == 10)
				{
					return d.Substring(0, 10) + "00GMT" + d.Substring(10, 3) + ":" + d.Substring(13, 2);
				}
				else
				{
					return d.Substring(0, 12) + "GMT" + d.Substring(12, 3) + ":" + d.Substring(15, 2);
				}
			}
		}

		/// <summary>
		/// Return a time string as an adjusted date with a 4 digit year. This goes
		/// in the range of 1950 - 2049.
		/// </summary>
		public virtual string getAdjustedTime()
		{
			string d = this.getTime();

			if (d[0] < '5')
			{
				return "20" + d;
			}
			else
			{
				return "19" + d;
			}
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
			@out.write(BERTags_Fields.UTC_TIME);

			int length = time.Length;

			@out.writeLength(length);

			for (int i = 0; i != length; i++)
			{
				@out.write((byte)time[i]);
			}
		}

		public override bool asn1Equals(ASN1Primitive o)
		{
			if (!(o is ASN1UTCTime))
			{
				return false;
			}

			return Arrays.areEqual(time, ((ASN1UTCTime)o).time);
		}

		public override int GetHashCode()
		{
			return Arrays.GetHashCode(time);
		}

		public override string ToString()
		{
		  return Strings.fromByteArray(time);
		}
	}

}