using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.pqc.asn1
{

	using ASN1EncodableVector = org.bouncycastle.asn1.ASN1EncodableVector;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1Object = org.bouncycastle.asn1.ASN1Object;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using ASN1TaggedObject = org.bouncycastle.asn1.ASN1TaggedObject;
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using DERSequence = org.bouncycastle.asn1.DERSequence;
	using DERTaggedObject = org.bouncycastle.asn1.DERTaggedObject;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// XMMSPrivateKey
	/// <pre>
	///     XMMSPrivateKey ::= SEQUENCE {
	///         version INTEGER -- 0
	///         keyData SEQUENCE {
	///            index         INTEGER
	///            secretKeySeed OCTET STRING
	///            secretKeyPRF  OCTET STRING
	///            publicSeed    OCTET STRING
	///            root          OCTET STRING
	///         }
	///         bdsState CHOICE {
	///            platformSerialization [0] OCTET STRING
	///         } OPTIONAL
	///    }
	/// </pre>
	/// </summary>
	public class XMSSPrivateKey : ASN1Object
	{
		private readonly int index;
		private readonly byte[] secretKeySeed;
		private readonly byte[] secretKeyPRF;
		private readonly byte[] publicSeed;
		private readonly byte[] root;
		private readonly byte[] bdsState;

		public XMSSPrivateKey(int index, byte[] secretKeySeed, byte[] secretKeyPRF, byte[] publicSeed, byte[] root, byte[] bdsState)
		{
			this.index = index;
			this.secretKeySeed = Arrays.clone(secretKeySeed);
			this.secretKeyPRF = Arrays.clone(secretKeyPRF);
			this.publicSeed = Arrays.clone(publicSeed);
			this.root = Arrays.clone(root);
			this.bdsState = Arrays.clone(bdsState);
		}

		private XMSSPrivateKey(ASN1Sequence seq)
		{
			if (!ASN1Integer.getInstance(seq.getObjectAt(0)).getValue().Equals(BigInteger.valueOf(0)))
			{
				throw new IllegalArgumentException("unknown version of sequence");
			}

			if (seq.size() != 2 && seq.size() != 3)
			{
				throw new IllegalArgumentException("key sequence wrong size");
			}

			ASN1Sequence keySeq = ASN1Sequence.getInstance(seq.getObjectAt(1));

			this.index = ASN1Integer.getInstance(keySeq.getObjectAt(0)).getValue().intValue();
			this.secretKeySeed = Arrays.clone(DEROctetString.getInstance(keySeq.getObjectAt(1)).getOctets());
			this.secretKeyPRF = Arrays.clone(DEROctetString.getInstance(keySeq.getObjectAt(2)).getOctets());
			this.publicSeed = Arrays.clone(DEROctetString.getInstance(keySeq.getObjectAt(3)).getOctets());
			this.root = Arrays.clone(DEROctetString.getInstance(keySeq.getObjectAt(4)).getOctets());

			if (seq.size() == 3)
			{
				this.bdsState = Arrays.clone(DEROctetString.getInstance(ASN1TaggedObject.getInstance(seq.getObjectAt(2)), true).getOctets());
			}
			else
			{
				this.bdsState = null;
			}
		}

		public static XMSSPrivateKey getInstance(object o)
		{
			if (o is XMSSPrivateKey)
			{
				return (XMSSPrivateKey)o;
			}
			else if (o != null)
			{
				return new XMSSPrivateKey(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public virtual int getIndex()
		{
			return index;
		}

		public virtual byte[] getSecretKeySeed()
		{
			return Arrays.clone(secretKeySeed);
		}

		public virtual byte[] getSecretKeyPRF()
		{
			return Arrays.clone(secretKeyPRF);
		}

		public virtual byte[] getPublicSeed()
		{
			return Arrays.clone(publicSeed);
		}

		public virtual byte[] getRoot()
		{
			return Arrays.clone(root);
		}

		public virtual byte[] getBdsState()
		{
			return Arrays.clone(bdsState);
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(new ASN1Integer(0)); // version

			ASN1EncodableVector vK = new ASN1EncodableVector();

			vK.add(new ASN1Integer(index));
			vK.add(new DEROctetString(secretKeySeed));
			vK.add(new DEROctetString(secretKeyPRF));
			vK.add(new DEROctetString(publicSeed));
			vK.add(new DEROctetString(root));

			v.add(new DERSequence(vK));
			v.add(new DERTaggedObject(true, 0, new DEROctetString(bdsState)));

			return new DERSequence(v);
		}
	}

}