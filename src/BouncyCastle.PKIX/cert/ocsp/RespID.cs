using org.bouncycastle.asn1.oiw;

using System;

namespace org.bouncycastle.cert.ocsp
{

	using DERNull = org.bouncycastle.asn1.DERNull;
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using ResponderID = org.bouncycastle.asn1.ocsp.ResponderID;
	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using DigestCalculator = org.bouncycastle.@operator.DigestCalculator;

	/// <summary>
	/// Carrier for a ResponderID.
	/// </summary>
	public class RespID
	{
		public static readonly AlgorithmIdentifier HASH_SHA1 = new AlgorithmIdentifier(OIWObjectIdentifiers_Fields.idSHA1, DERNull.INSTANCE);

		internal ResponderID id;

		public RespID(ResponderID id)
		{
			this.id = id;
		}

		public RespID(X500Name name)
		{
			this.id = new ResponderID(name);
		}

		/// <summary>
		/// Calculate a RespID based on the public key of the responder.
		/// </summary>
		/// <param name="subjectPublicKeyInfo"> the info structure for the responder public key. </param>
		/// <param name="digCalc"> a SHA-1 digest calculator. </param>
		/// <exception cref="OCSPException"> on exception creating ID. </exception>
		public RespID(SubjectPublicKeyInfo subjectPublicKeyInfo, DigestCalculator digCalc)
		{
			try
			{
				if (!digCalc.getAlgorithmIdentifier().Equals(HASH_SHA1))
				{
					throw new IllegalArgumentException("only SHA-1 can be used with RespID - found: " + digCalc.getAlgorithmIdentifier().getAlgorithm());
				}

				OutputStream digOut = digCalc.getOutputStream();

				digOut.write(subjectPublicKeyInfo.getPublicKeyData().getBytes());
				digOut.close();

				this.id = new ResponderID(new DEROctetString(digCalc.getDigest()));
			}
			catch (Exception e)
			{
				throw new OCSPException("problem creating ID: " + e, e);
			}
		}

		public virtual ResponderID toASN1Primitive()
		{
			return id;
		}

		public override bool Equals(object o)
		{
			if (!(o is RespID))
			{
				return false;
			}

			RespID obj = (RespID)o;

			return id.Equals(obj.id);
		}

		public override int GetHashCode()
		{
			return id.GetHashCode();
		}
	}

}