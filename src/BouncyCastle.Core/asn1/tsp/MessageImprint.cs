namespace org.bouncycastle.asn1.tsp
{
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using Arrays = org.bouncycastle.util.Arrays;

	public class MessageImprint : ASN1Object
	{
		internal AlgorithmIdentifier hashAlgorithm;
		internal byte[] hashedMessage;

		/// <param name="o"> </param>
		/// <returns> a MessageImprint object. </returns>
		public static MessageImprint getInstance(object o)
		{
			if (o is MessageImprint)
			{
				return (MessageImprint)o;
			}

			if (o != null)
			{
				return new MessageImprint(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		private MessageImprint(ASN1Sequence seq)
		{
			this.hashAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
			this.hashedMessage = ASN1OctetString.getInstance(seq.getObjectAt(1)).getOctets();
		}

		public MessageImprint(AlgorithmIdentifier hashAlgorithm, byte[] hashedMessage)
		{
			this.hashAlgorithm = hashAlgorithm;
			this.hashedMessage = Arrays.clone(hashedMessage);
		}

		public virtual AlgorithmIdentifier getHashAlgorithm()
		{
			return hashAlgorithm;
		}

		public virtual byte[] getHashedMessage()
		{
			return Arrays.clone(hashedMessage);
		}

		/// <summary>
		/// <pre>
		///    MessageImprint ::= SEQUENCE  {
		///       hashAlgorithm                AlgorithmIdentifier,
		///       hashedMessage                OCTET STRING  }
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(hashAlgorithm);
			v.add(new DEROctetString(hashedMessage));

			return new DERSequence(v);
		}
	}

}