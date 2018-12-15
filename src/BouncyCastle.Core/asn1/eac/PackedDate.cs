using BouncyCastle.Core.Port.java.text;
using org.bouncycastle.Port.java.text;

namespace org.bouncycastle.asn1.eac
{

	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// EAC encoding date object
	/// </summary>
	public class PackedDate
	{
		private byte[] time;

		public PackedDate(string time)
		{
			this.time = convert(time);
		}

		/// <summary>
		/// Base constructor from a java.util.date object.
		/// </summary>
		/// <param name="time"> a date object representing the time of interest. </param>
		public PackedDate(DateTime time)
		{
			SimpleDateFormat dateF = new SimpleDateFormat("yyMMdd'Z'");

			dateF.setTimeZone(new SimpleTimeZone(0,"Z"));

			this.time = convert(dateF.format(time));
		}

		/// <summary>
		/// Base constructor from a java.util.date object. You may need to use this constructor if the default locale
		/// doesn't use a Gregorian calender so that the PackedDate produced is compatible with other ASN.1 implementations.
		/// </summary>
		/// <param name="time"> a date object representing the time of interest. </param>
		/// <param name="locale"> an appropriate Locale for producing an ASN.1 GeneralizedTime value. </param>
		public PackedDate(DateTime time, Locale locale)
		{
			SimpleDateFormat dateF = new SimpleDateFormat("yyMMdd'Z'", locale);

			dateF.setTimeZone(new SimpleTimeZone(0,"Z"));

			this.time = convert(dateF.format(time));
		}

		private byte[] convert(string sTime)
		{
			char[] digs = sTime.ToCharArray();
			byte[] date = new byte[6];

			for (int i = 0; i != 6; i++)
			{
				date[i] = (byte)(digs[i] - '0');
			}

			return date;
		}

		public PackedDate(byte[] bytes)
		{
			this.time = bytes;
		}

		/// <summary>
		/// return the time as a date based on whatever a 2 digit year will return. For
		/// standardised processing use getAdjustedDate().
		/// </summary>
		/// <returns> the resulting date </returns>
		/// <exception cref="ParseException"> if the date string cannot be parsed. </exception>
		public virtual DateTime getDate()
		{
			SimpleDateFormat dateF = new SimpleDateFormat("yyyyMMdd");

			return dateF.parse("20" + ToString());
		}

		public override int GetHashCode()
		{
			return Arrays.GetHashCode(time);
		}

		public override bool Equals(object o)
		{
			if (!(o is PackedDate))
			{
				return false;
			}

			PackedDate other = (PackedDate)o;

			return Arrays.areEqual(time, other.time);
		}

		public override string ToString()
		{
			char[] dateC = new char[time.Length];

			for (int i = 0; i != dateC.Length; i++)
			{
				dateC[i] = (char)((time[i] & 0xff) + '0');
			}

			return new string(dateC);
		}

		public virtual byte[] getEncoding()
		{
			return Arrays.clone(time);
		}
	}

}