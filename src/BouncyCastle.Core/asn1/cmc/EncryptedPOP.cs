using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cmc
{
	using ContentInfo = org.bouncycastle.asn1.cms.ContentInfo;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// <pre>
	///      id-cmc-encryptedPOP OBJECT IDENTIFIER ::= {id-cmc 9}
	/// 
	///      EncryptedPOP ::= SEQUENCE {
	///              request       TaggedRequest,
	///              cms             ContentInfo,
	///              thePOPAlgID     AlgorithmIdentifier,
	///              witnessAlgID    AlgorithmIdentifier,
	///              witness         OCTET STRING
	///      }
	/// </pre>
	/// </summary>
	public class EncryptedPOP : ASN1Object
	{
		private readonly TaggedRequest request;
		private readonly ContentInfo cms;
		private readonly AlgorithmIdentifier thePOPAlgID;
		private readonly AlgorithmIdentifier witnessAlgID;
		private readonly byte[] witness;

		private EncryptedPOP(ASN1Sequence seq)
		{
			if (seq.size() != 5)
			{
				throw new IllegalArgumentException("incorrect sequence size");
			}
			this.request = TaggedRequest.getInstance(seq.getObjectAt(0));
			this.cms = ContentInfo.getInstance(seq.getObjectAt(1));
			this.thePOPAlgID = AlgorithmIdentifier.getInstance(seq.getObjectAt(2));
			this.witnessAlgID = AlgorithmIdentifier.getInstance(seq.getObjectAt(3));
			this.witness = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(4)).getOctets());
		}

		public EncryptedPOP(TaggedRequest request, ContentInfo cms, AlgorithmIdentifier thePOPAlgID, AlgorithmIdentifier witnessAlgID, byte[] witness)
		{
			this.request = request;
			this.cms = cms;
			this.thePOPAlgID = thePOPAlgID;
			this.witnessAlgID = witnessAlgID;
			this.witness = Arrays.clone(witness);
		}

		public static EncryptedPOP getInstance(object o)
		{
			if (o is EncryptedPOP)
			{
				return (EncryptedPOP)o;
			}

			if (o != null)
			{
				return new EncryptedPOP(ASN1Sequence.getInstance(o));
			}

			return null;
		}


		public virtual TaggedRequest getRequest()
		{
			return request;
		}

		public virtual ContentInfo getCms()
		{
			return cms;
		}

		public virtual AlgorithmIdentifier getThePOPAlgID()
		{
			return thePOPAlgID;
		}

		public virtual AlgorithmIdentifier getWitnessAlgID()
		{
			return witnessAlgID;
		}

		public virtual byte[] getWitness()
		{
			return Arrays.clone(witness);
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(request);
			v.add(cms);
			v.add(thePOPAlgID);
			v.add(witnessAlgID);
			v.add(new DEROctetString(witness));

			return new DERSequence(v);
		}
	}

}