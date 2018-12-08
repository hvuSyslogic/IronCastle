using System.IO;
using org.bouncycastle.Port;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1
{

	/// <summary>
	/// ASN.1 OctetStrings, with indefinite length rules, and <i>constructed form</i> support.
	/// <para>
	/// The Basic Encoding Rules (BER) format allows encoding using so called "<i>constructed form</i>",
	/// which DER and CER formats forbid allowing only "primitive form".
	/// </para>
	/// </para><para>
	/// This class <b>always</b> produces the constructed form with underlying segments
	/// in an indefinite length array.  If the input wasn't the same, then this output
	/// is not faithful reproduction.
	/// </p>
	/// <para>
	/// See <seealso cref="ASN1OctetString"/> for X.690 encoding rules of OCTET-STRING objects.
	/// </para>
	/// </summary>
	public class BEROctetString : ASN1OctetString
	{
		private const int DEFAULT_LENGTH = 1000;

		private readonly int chunkSize;
		private readonly ASN1OctetString[] octs;

		/// <summary>
		/// Convert a vector of octet strings into a single byte string
		/// </summary>
		private static byte[] toBytes(ASN1OctetString[] octs)
		{
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			for (int i = 0; i != octs.Length; i++)
			{
				try
				{
					DEROctetString o = (DEROctetString)octs[i];

					bOut.write(o.getOctets());
				}
				catch (ClassCastException)
				{
					throw new IllegalArgumentException(octs[i].GetType().getName() + " found in input should only contain DEROctetString");
				}
				catch (IOException e)
				{
					throw new IllegalArgumentException("exception converting octets " + e.ToString());
				}
			}

			return bOut.toByteArray();
		}

		/// <summary>
		/// Create an OCTET-STRING object from a byte[] </summary>
		/// <param name="string"> the octets making up the octet string. </param>
		public BEROctetString(byte[] @string) : this(@string, DEFAULT_LENGTH)
		{
		}

		/// <summary>
		/// Multiple <seealso cref="ASN1OctetString"/> data blocks are input,
		/// the result is <i>constructed form</i>.
		/// </summary>
		/// <param name="octs"> an array of OCTET STRING to construct the BER OCTET STRING from. </param>
		public BEROctetString(ASN1OctetString[] octs) : this(octs, DEFAULT_LENGTH)
		{
		}

		/// <summary>
		/// Create an OCTET-STRING object from a byte[] </summary>
		/// <param name="string"> the octets making up the octet string. </param>
		/// <param name="chunkSize"> the number of octets stored in each DER encoded component OCTET STRING. </param>
		public BEROctetString(byte[] @string, int chunkSize) : this(@string, null, chunkSize)
		{
		}

		/// <summary>
		/// Multiple <seealso cref="ASN1OctetString"/> data blocks are input,
		/// the result is <i>constructed form</i>.
		/// </summary>
		/// <param name="octs"> an array of OCTET STRING to construct the BER OCTET STRING from. </param>
		/// <param name="chunkSize"> the number of octets stored in each DER encoded component OCTET STRING. </param>
		public BEROctetString(ASN1OctetString[] octs, int chunkSize) : this(toBytes(octs), octs, chunkSize)
		{
		}

		private BEROctetString(byte[] @string, ASN1OctetString[] octs, int chunkSize) : base(@string)
		{
			this.octs = octs;
			this.chunkSize = chunkSize;
		}

		/// <summary>
		/// Return a concatenated byte array of all the octets making up the constructed OCTET STRING </summary>
		/// <returns> the full OCTET STRING. </returns>
		public override byte[] getOctets()
		{
			return @string;
		}

		/// <summary>
		/// Return the OCTET STRINGs that make up this string.
		/// </summary>
		/// <returns> an Enumeration of the component OCTET STRINGs. </returns>
		public virtual Enumeration getObjects()
		{
			if (octs == null)
			{
				return generateOcts().elements();
			}

			return new EnumerationAnonymousInnerClass(this);
		}

		public class EnumerationAnonymousInnerClass : Enumeration
		{
			private readonly BEROctetString outerInstance;

			public EnumerationAnonymousInnerClass(BEROctetString outerInstance)
			{
				this.outerInstance = outerInstance;
				counter = 0;
			}

			internal int counter;

			public bool hasMoreElements()
			{
				return counter < outerInstance.octs.Length;
			}

			public object nextElement()
			{
				return outerInstance.octs[counter++];
			}
		}

		private Vector generateOcts()
		{
			Vector vec = new Vector();
			for (int i = 0; i < @string.Length; i += chunkSize)
			{
				int end;

				if (i + chunkSize > @string.Length)
				{
					end = @string.Length;
				}
				else
				{
					end = i + chunkSize;
				}

				byte[] nStr = new byte[end - i];

				JavaSystem.arraycopy(@string, i, nStr, 0, nStr.Length);

				vec.addElement(new DEROctetString(nStr));
			}

			 return vec;
		}

		public override bool isConstructed()
		{
			return true;
		}

		public override int encodedLength()
		{
			int length = 0;
			for (Enumeration e = getObjects(); e.hasMoreElements();)
			{
				length += ((ASN1Encodable)e.nextElement()).toASN1Primitive().encodedLength();
			}

			return 2 + length + 2;
		}

		public override void encode(ASN1OutputStream @out)
		{
			@out.write(BERTags_Fields.CONSTRUCTED | BERTags_Fields.OCTET_STRING);

			@out.write(0x80);

			//
			// write out the octet array
			//
			for (Enumeration e = getObjects(); e.hasMoreElements();)
			{
				@out.writeObject((ASN1Encodable)e.nextElement());
			}

			@out.write(0x00);
			@out.write(0x00);
		}

		internal static BEROctetString fromSequence(ASN1Sequence seq)
		{
			ASN1OctetString[] v = new ASN1OctetString[seq.size()];
			Enumeration e = seq.getObjects();
			int index = 0;

			while (e.hasMoreElements())
			{
				v[index++] = (ASN1OctetString)e.nextElement();
			}

			return new BEROctetString(v);
		}
	}

}