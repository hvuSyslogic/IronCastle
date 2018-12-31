using BouncyCastle.Core.Port.java.text;
using org.bouncycastle.Port;
using org.bouncycastle.util;

namespace org.bouncycastle.asn1
{

	
	/// <summary>
	/// DER Generalized time object.
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
	public class DERGeneralizedTime : ASN1GeneralizedTime
	{
		public DERGeneralizedTime(byte[] time) : base(time)
		{
		}

		public DERGeneralizedTime(DateTime time) : base(time)
		{
		}

		public DERGeneralizedTime(string time) : base(time)
		{
		}

		private byte[] getDERTime()
		{
			if (time[time.Length - 1] == (byte)'Z')
			{
				if (!hasMinutes())
				{
					byte[] derTime = new byte[time.Length + 4];

					JavaSystem.arraycopy(time, 0, derTime, 0, time.Length - 1);
					JavaSystem.arraycopy(Strings.toByteArray("0000Z"), 0, derTime, time.Length - 1, 5);

					return derTime;
				}
				else if (!hasSeconds())
				{
					byte[] derTime = new byte[time.Length + 2];

					JavaSystem.arraycopy(time, 0, derTime, 0, time.Length - 1);
					JavaSystem.arraycopy(Strings.toByteArray("00Z"), 0, derTime, time.Length - 1, 3);

					return derTime;
				}
				else if (hasFractionalSeconds())
				{
					int ind = time.Length - 2;
					while (ind > 0 && time[ind] == (byte)'0')
					{
						ind--;
					}

					if (time[ind] == (byte)'.')
					{
						byte[] derTime = new byte[ind + 1];

						JavaSystem.arraycopy(time, 0, derTime, 0, ind);
						derTime[ind] = (byte)'Z';

						return derTime;
					}
					else
					{
						byte[] derTime = new byte[ind + 2];

						JavaSystem.arraycopy(time, 0, derTime, 0, ind + 1);
						derTime[ind + 1] = (byte)'Z';

						return derTime;
					}
				}
				else
				{
					return time;
				}
			}
			else
			{
				return time; // TODO: is there a better way?
			}
		}

		public override int encodedLength()
		{
			int length = getDERTime().Length;

			return 1 + StreamUtil.calculateBodyLength(length) + length;
		}

		public override void encode(ASN1OutputStream @out)
		{
			@out.writeEncoded(BERTags_Fields.GENERALIZED_TIME, getDERTime());
		}
	}

}