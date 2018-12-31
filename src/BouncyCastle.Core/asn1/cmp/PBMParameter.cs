﻿using org.bouncycastle.asn1.x509;

namespace org.bouncycastle.asn1.cmp
{
	
	public class PBMParameter : ASN1Object
	{
		private ASN1OctetString salt;
		private AlgorithmIdentifier owf;
		private ASN1Integer iterationCount;
		private AlgorithmIdentifier mac;

		private PBMParameter(ASN1Sequence seq)
		{
			salt = ASN1OctetString.getInstance(seq.getObjectAt(0));
			owf = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
			iterationCount = ASN1Integer.getInstance(seq.getObjectAt(2));
			mac = AlgorithmIdentifier.getInstance(seq.getObjectAt(3));
		}

		public static PBMParameter getInstance(object o)
		{
			if (o is PBMParameter)
			{
				return (PBMParameter)o;
			}

			if (o != null)
			{
				return new PBMParameter(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public PBMParameter(byte[] salt, AlgorithmIdentifier owf, int iterationCount, AlgorithmIdentifier mac) : this(new DEROctetString(salt), owf, new ASN1Integer(iterationCount), mac)
		{
		}

		public PBMParameter(ASN1OctetString salt, AlgorithmIdentifier owf, ASN1Integer iterationCount, AlgorithmIdentifier mac)
		{
			this.salt = salt;
			this.owf = owf;
			this.iterationCount = iterationCount;
			this.mac = mac;
		}

		public virtual ASN1OctetString getSalt()
		{
			return salt;
		}

		public virtual AlgorithmIdentifier getOwf()
		{
			return owf;
		}

		public virtual ASN1Integer getIterationCount()
		{
			return iterationCount;
		}

		public virtual AlgorithmIdentifier getMac()
		{
			return mac;
		}

		/// <summary>
		/// <pre>
		///  PBMParameter ::= SEQUENCE {
		///                        salt                OCTET STRING,
		///                        -- note:  implementations MAY wish to limit acceptable sizes
		///                        -- of this string to values appropriate for their environment
		///                        -- in order to reduce the risk of denial-of-service attacks
		///                        owf                 AlgorithmIdentifier,
		///                        -- AlgId for a One-Way Function (SHA-1 recommended)
		///                        iterationCount      INTEGER,
		///                        -- number of times the OWF is applied
		///                        -- note:  implementations MAY wish to limit acceptable sizes
		///                        -- of this integer to values appropriate for their environment
		///                        -- in order to reduce the risk of denial-of-service attacks
		///                        mac                 AlgorithmIdentifier
		///                        -- the MAC AlgId (e.g., DES-MAC, Triple-DES-MAC [PKCS11],
		///    }   -- or HMAC [RFC2104, RFC2202])
		/// </pre> </summary>
		/// <returns> a basic ASN.1 object representation. </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(salt);
			v.add(owf);
			v.add(iterationCount);
			v.add(mac);

			return new DERSequence(v);
		}
	}

}