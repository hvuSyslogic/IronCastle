﻿using org.bouncycastle.asn1.x509;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;

namespace org.bouncycastle.asn1.cryptopro
{
		
	/// <summary>
	///  <pre>
	/// GostR3410-TransportParameters ::= SEQUENCE {
	///        encryptionParamSet   OBJECT IDENTIFIER,
	///        ephemeralPublicKey   [0] IMPLICIT SubjectPublicKeyInfo OPTIONAL,
	///        ukm                  OCTET STRING
	/// }
	///  </pre>
	/// </summary>
	public class GostR3410TransportParameters : ASN1Object
	{
		private readonly ASN1ObjectIdentifier encryptionParamSet;
		private readonly SubjectPublicKeyInfo ephemeralPublicKey;
		private readonly byte[] ukm;

		public GostR3410TransportParameters(ASN1ObjectIdentifier encryptionParamSet, SubjectPublicKeyInfo ephemeralPublicKey, byte[] ukm)
		{
			this.encryptionParamSet = encryptionParamSet;
			this.ephemeralPublicKey = ephemeralPublicKey;
			this.ukm = Arrays.clone(ukm);
		}

		private GostR3410TransportParameters(ASN1Sequence seq)
		{
			if (seq.size() == 2)
			{
				this.encryptionParamSet = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
				this.ukm = ASN1OctetString.getInstance(seq.getObjectAt(1)).getOctets();
				this.ephemeralPublicKey = null;
			}
			else if (seq.size() == 3)
			{
				this.encryptionParamSet = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
				this.ephemeralPublicKey = SubjectPublicKeyInfo.getInstance(ASN1TaggedObject.getInstance(seq.getObjectAt(1)), false);
				this.ukm = ASN1OctetString.getInstance(seq.getObjectAt(2)).getOctets();
			}
			else
			{
				throw new IllegalArgumentException("unknown sequence length: " + seq.size());
			}
		}

		public static GostR3410TransportParameters getInstance(object obj)
		{
			if (obj is GostR3410TransportParameters)
			{
				return (GostR3410TransportParameters)obj;
			}

			if (obj != null)
			{
				return new GostR3410TransportParameters(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public static GostR3410TransportParameters getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return new GostR3410TransportParameters(ASN1Sequence.getInstance(obj, @explicit));
		}

		public virtual ASN1ObjectIdentifier getEncryptionParamSet()
		{
			return encryptionParamSet;
		}

		public virtual SubjectPublicKeyInfo getEphemeralPublicKey()
		{
			return ephemeralPublicKey;
		}

		public virtual byte[] getUkm()
		{
			return Arrays.clone(ukm);
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(encryptionParamSet);

			if (ephemeralPublicKey != null)
			{
				v.add(new DERTaggedObject(false, 0, ephemeralPublicKey));
			}

			v.add(new DEROctetString(ukm));

			return new DERSequence(v);
		}
	}

}