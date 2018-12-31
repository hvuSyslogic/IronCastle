using BouncyCastle.Core.Port;
using org.bouncycastle.asn1.x509;
using org.bouncycastle.Port.java.util;
using org.bouncycastle.util;

namespace org.bouncycastle.asn1.pkcs
{

		
	/// <summary>
	/// <pre>
	///     PBKDF2-params ::= SEQUENCE {
	///               salt CHOICE {
	///                      specified OCTET STRING,
	///                      otherSource AlgorithmIdentifier {{PBKDF2-SaltSources}}
	///               },
	///              iterationCount INTEGER (1..MAX),
	///              keyLength INTEGER (1..MAX) OPTIONAL,
	///              prf AlgorithmIdentifier {{PBKDF2-PRFs}} DEFAULT algid-hmacWithSHA1 }
	/// </pre>
	/// </summary>
	public class PBKDF2Params : ASN1Object
	{
		private static readonly AlgorithmIdentifier algid_hmacWithSHA1 = new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.id_hmacWithSHA1, DERNull.INSTANCE);

		private readonly ASN1OctetString octStr;
		private readonly ASN1Integer iterationCount;
		private readonly ASN1Integer keyLength;
		private readonly AlgorithmIdentifier prf;

		/// <summary>
		/// Create PBKDF2Params from the passed in object,
		/// </summary>
		/// <param name="obj"> either PBKDF2Params or an ASN1Sequence. </param>
		/// <returns> a PBKDF2Params instance. </returns>
		public static PBKDF2Params getInstance(object obj)
		{
			if (obj is PBKDF2Params)
			{
				return (PBKDF2Params)obj;
			}

			if (obj != null)
			{
				return new PBKDF2Params(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		/// <summary>
		/// Create a PBKDF2Params with the specified salt, iteration count, and algid-hmacWithSHA1 for the prf.
		/// </summary>
		/// <param name="salt">           input salt. </param>
		/// <param name="iterationCount"> input iteration count. </param>
		public PBKDF2Params(byte[] salt, int iterationCount) : this(salt, iterationCount, 0)
		{
		}

		/// <summary>
		/// Create a PBKDF2Params with the specified salt, iteration count, keyLength, and algid-hmacWithSHA1 for the prf.
		/// </summary>
		/// <param name="salt">           input salt. </param>
		/// <param name="iterationCount"> input iteration count. </param>
		/// <param name="keyLength">      intended key length to be produced. </param>
		public PBKDF2Params(byte[] salt, int iterationCount, int keyLength) : this(salt, iterationCount, keyLength, null)
		{
		}

		/// <summary>
		/// Create a PBKDF2Params with the specified salt, iteration count, keyLength, and a defined prf.
		/// </summary>
		/// <param name="salt">           input salt. </param>
		/// <param name="iterationCount"> input iteration count. </param>
		/// <param name="keyLength">      intended key length to be produced. </param>
		/// <param name="prf">            the pseudo-random function to use. </param>
		public PBKDF2Params(byte[] salt, int iterationCount, int keyLength, AlgorithmIdentifier prf)
		{
			this.octStr = new DEROctetString(Arrays.clone(salt));
			this.iterationCount = new ASN1Integer(iterationCount);

			if (keyLength > 0)
			{
				this.keyLength = new ASN1Integer(keyLength);
			}
			else
			{
				this.keyLength = null;
			}

			this.prf = prf;
		}

		/// <summary>
		/// Create a PBKDF2Params with the specified salt, iteration count, and a defined prf.
		/// </summary>
		/// <param name="salt">           input salt. </param>
		/// <param name="iterationCount"> input iteration count. </param>
		/// <param name="prf">            the pseudo-random function to use. </param>
		public PBKDF2Params(byte[] salt, int iterationCount, AlgorithmIdentifier prf) : this(salt, iterationCount, 0, prf)
		{
		}

		private PBKDF2Params(ASN1Sequence seq)
		{
			Enumeration e = seq.getObjects();

			octStr = (ASN1OctetString)e.nextElement();
			iterationCount = (ASN1Integer)e.nextElement();

			if (e.hasMoreElements())
			{
				object o = e.nextElement();

				if (o is ASN1Integer)
				{
					keyLength = ASN1Integer.getInstance(o);
					if (e.hasMoreElements())
					{
						o = e.nextElement();
					}
					else
					{
						o = null;
					}
				}
				else
				{
					keyLength = null;
				}

				if (o != null)
				{
					prf = AlgorithmIdentifier.getInstance(o);
				}
				else
				{
					prf = null;
				}
			}
			else
			{
				keyLength = null;
				prf = null;
			}
		}

		/// <summary>
		/// Return the salt to use.
		/// </summary>
		/// <returns> the input salt. </returns>
		public virtual byte[] getSalt()
		{
			return octStr.getOctets();
		}

		/// <summary>
		/// Return the iteration count to use.
		/// </summary>
		/// <returns> the input iteration count. </returns>
		public virtual BigInteger getIterationCount()
		{
			return iterationCount.getValue();
		}

		/// <summary>
		/// Return the intended length in octets of the derived key.
		/// </summary>
		/// <returns> length in octets for derived key, if specified. </returns>
		public virtual BigInteger getKeyLength()
		{
			if (keyLength != null)
			{
				return keyLength.getValue();
			}

			return null;
		}

		/// <summary>
		/// Return true if the PRF is the default (hmacWithSHA1)
		/// </summary>
		/// <returns> true if PRF is default, false otherwise. </returns>
		public virtual bool isDefaultPrf()
		{
			return prf == null || prf.Equals(algid_hmacWithSHA1);
		}

		/// <summary>
		/// Return the algId of the underlying pseudo random function to use.
		/// </summary>
		/// <returns> the prf algorithm identifier. </returns>
		public virtual AlgorithmIdentifier getPrf()
		{
			if (prf != null)
			{
				return prf;
			}

			return algid_hmacWithSHA1;
		}

		/// <summary>
		/// Return an ASN.1 structure suitable for encoding.
		/// </summary>
		/// <returns> the object as an ASN.1 encodable structure. </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(octStr);
			v.add(iterationCount);

			if (keyLength != null)
			{
				v.add(keyLength);
			}

			if (prf != null && !prf.Equals(algid_hmacWithSHA1))
			{
				v.add(prf);
			}

			return new DERSequence(v);
		}
	}

}