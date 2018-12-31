using org.bouncycastle.asn1.x509;

namespace org.bouncycastle.asn1.dvcs
{
	
	/// <summary>
	/// <pre>
	///     DVCSRequest ::= SEQUENCE  {
	///         requestInformation         DVCSRequestInformation,
	///         data                       Data,
	///         transactionIdentifier      GeneralName OPTIONAL
	///     }
	/// </pre>
	/// </summary>

	public class DVCSRequest : ASN1Object
	{

		private DVCSRequestInformation requestInformation;
		private Data data;
		private GeneralName transactionIdentifier;

		public DVCSRequest(DVCSRequestInformation requestInformation, Data data) : this(requestInformation, data, null)
		{
		}

		public DVCSRequest(DVCSRequestInformation requestInformation, Data data, GeneralName transactionIdentifier)
		{
			this.requestInformation = requestInformation;
			this.data = data;
			this.transactionIdentifier = transactionIdentifier;
		}

		private DVCSRequest(ASN1Sequence seq)
		{
			requestInformation = DVCSRequestInformation.getInstance(seq.getObjectAt(0));
			data = Data.getInstance(seq.getObjectAt(1));
			if (seq.size() > 2)
			{
				transactionIdentifier = GeneralName.getInstance(seq.getObjectAt(2));
			}
		}

		public static DVCSRequest getInstance(object obj)
		{
			if (obj is DVCSRequest)
			{
				return (DVCSRequest)obj;
			}
			else if (obj != null)
			{
				return new DVCSRequest(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public static DVCSRequest getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();
			v.add(requestInformation);
			v.add(data);
			if (transactionIdentifier != null)
			{
				v.add(transactionIdentifier);
			}
			return new DERSequence(v);
		}

		public override string ToString()
		{
			return "DVCSRequest {\n" +
				"requestInformation: " + requestInformation + "\n" +
				"data: " + data + "\n" +
				(transactionIdentifier != null ? "transactionIdentifier: " + transactionIdentifier + "\n" : "") +
				"}\n";
		}

		public virtual Data getData()
		{
			return data;
		}

		public virtual DVCSRequestInformation getRequestInformation()
		{
			return requestInformation;
		}

		public virtual GeneralName getTransactionIdentifier()
		{
			return transactionIdentifier;
		}
	}

}