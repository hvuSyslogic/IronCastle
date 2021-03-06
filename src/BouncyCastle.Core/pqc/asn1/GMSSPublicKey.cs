﻿using org.bouncycastle.asn1;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;

namespace org.bouncycastle.pqc.asn1
{
									
	/// <summary>
	/// This class implements an ASN.1 encoded GMSS public key. The ASN.1 definition
	/// of this structure is:
	/// <pre>
	///  GMSSPublicKey        ::= SEQUENCE{
	///      version         INTEGER
	///      publicKey       OCTET STRING
	///  }
	/// </pre>
	/// </summary>
	public class GMSSPublicKey : ASN1Object
	{
		private ASN1Integer version;
		private byte[] publicKey;

		private GMSSPublicKey(ASN1Sequence seq)
		{
			if (seq.size() != 2)
			{
				throw new IllegalArgumentException("size of seq = " + seq.size());
			}

			this.version = ASN1Integer.getInstance(seq.getObjectAt(0));
			this.publicKey = ASN1OctetString.getInstance(seq.getObjectAt(1)).getOctets();
		}

		public GMSSPublicKey(byte[] publicKeyBytes)
		{
			this.version = new ASN1Integer(0);
			this.publicKey = publicKeyBytes;
		}

		public static GMSSPublicKey getInstance(object o)
		{
			if (o is GMSSPublicKey)
			{
				return (GMSSPublicKey)o;
			}
			else if (o != null)
			{
				return new GMSSPublicKey(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public virtual byte[] getPublicKey()
		{
			return Arrays.clone(publicKey);
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(version);
			v.add(new DEROctetString(publicKey));

			return new DERSequence(v);
		}
	}

}