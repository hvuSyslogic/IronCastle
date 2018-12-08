using System.IO;
using org.bouncycastle.Port;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1
{

	/// @deprecated use BEROctetString 
	public class BERConstructedOctetString : BEROctetString
	{
		private const int MAX_LENGTH = 1000;

		/// <summary>
		/// convert a vector of octet strings into a single byte string
		/// </summary>
		private static byte[] toBytes(Vector octs)
		{
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			for (int i = 0; i != octs.size(); i++)
			{
				try
				{
					DEROctetString o = (DEROctetString)octs.elementAt(i);

					bOut.write(o.getOctets());
				}
				catch (ClassCastException)
				{
					throw new IllegalArgumentException(octs.elementAt(i).GetType().getName() + " found in input should only contain DEROctetString");
				}
				catch (IOException e)
				{
					throw new IllegalArgumentException("exception converting octets " + e.ToString());
				}
			}

			return bOut.toByteArray();
		}

		private Vector octs;

		/// <param name="string"> the octets making up the octet string. </param>
		public BERConstructedOctetString(byte[] @string) : base(@string)
		{
		}

		public BERConstructedOctetString(Vector octs) : base(toBytes(octs))
		{

			this.octs = octs;
		}

		public BERConstructedOctetString(ASN1Primitive obj) : base(toByteArray(obj))
		{
		}

		private static byte[] toByteArray(ASN1Primitive obj)
		{
			try
			{
				return obj.getEncoded();
			}
			catch (IOException)
			{
				throw new IllegalArgumentException("Unable to encode object");
			}
		}

		public BERConstructedOctetString(ASN1Encodable obj) : this(obj.toASN1Primitive())
		{
		}

		public override byte[] getOctets()
		{
			return @string;
		}

		/// <summary>
		/// return the DER octets that make up this string.
		/// </summary>
		public override Enumeration getObjects()
		{
			if (octs == null)
			{
				return generateOcts().elements();
			}

			return octs.elements();
		}

		private Vector generateOcts()
		{
			Vector vec = new Vector();
			for (int i = 0; i < @string.Length; i += MAX_LENGTH)
			{
				int end;

				if (i + MAX_LENGTH > @string.Length)
				{
					end = @string.Length;
				}
				else
				{
					end = i + MAX_LENGTH;
				}

				byte[] nStr = new byte[end - i];

				JavaSystem.arraycopy(@string, i, nStr, 0, nStr.Length);

				vec.addElement(new DEROctetString(nStr));
			}

			 return vec;
		}

		public static BEROctetString fromSequence(ASN1Sequence seq)
		{
			Vector v = new Vector();
			Enumeration e = seq.getObjects();

			while (e.hasMoreElements())
			{
				v.addElement(e.nextElement());
			}

			return new BERConstructedOctetString(v);
		}
	}

}