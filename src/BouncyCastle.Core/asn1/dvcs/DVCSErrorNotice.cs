namespace org.bouncycastle.asn1.dvcs
{
	using PKIStatusInfo = org.bouncycastle.asn1.cmp.PKIStatusInfo;
	using GeneralName = org.bouncycastle.asn1.x509.GeneralName;

	/// <summary>
	/// <pre>
	///     DVCSErrorNotice ::= SEQUENCE {
	///         transactionStatus           PKIStatusInfo ,
	///         transactionIdentifier       GeneralName OPTIONAL
	///     }
	/// </pre>
	/// </summary>
	public class DVCSErrorNotice : ASN1Object
	{
		private PKIStatusInfo transactionStatus;
		private GeneralName transactionIdentifier;

		public DVCSErrorNotice(PKIStatusInfo status) : this(status, null)
		{
		}

		public DVCSErrorNotice(PKIStatusInfo status, GeneralName transactionIdentifier)
		{
			this.transactionStatus = status;
			this.transactionIdentifier = transactionIdentifier;
		}

		private DVCSErrorNotice(ASN1Sequence seq)
		{
			this.transactionStatus = PKIStatusInfo.getInstance(seq.getObjectAt(0));
			if (seq.size() > 1)
			{
				this.transactionIdentifier = GeneralName.getInstance(seq.getObjectAt(1));
			}
		}

		public static DVCSErrorNotice getInstance(object obj)
		{
			if (obj is DVCSErrorNotice)
			{
				return (DVCSErrorNotice)obj;
			}
			else if (obj != null)
			{
				return new DVCSErrorNotice(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public static DVCSErrorNotice getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();
			v.add(transactionStatus);
			if (transactionIdentifier != null)
			{
				v.add(transactionIdentifier);
			}
			return new DERSequence(v);
		}

		public override string ToString()
		{
			return "DVCSErrorNotice {\n" +
				"transactionStatus: " + transactionStatus + "\n" +
				(transactionIdentifier != null ? "transactionIdentifier: " + transactionIdentifier + "\n" : "") +
				"}\n";
		}


		public virtual PKIStatusInfo getTransactionStatus()
		{
			return transactionStatus;
		}

		public virtual GeneralName getTransactionIdentifier()
		{
			return transactionIdentifier;
		}
	}

}