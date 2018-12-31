using org.bouncycastle.asn1.x509;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.dvcs
{
	
	/// <summary>
	/// <pre>
	/// Data ::= CHOICE {
	///   message           OCTET STRING ,
	///   messageImprint    DigestInfo,
	///   certs             [0] SEQUENCE SIZE (1..MAX) OF
	///                         TargetEtcChain
	/// }
	/// </pre>
	/// </summary>

	public class Data : ASN1Object, ASN1Choice
	{
		private ASN1OctetString message;
		private DigestInfo messageImprint;
		private ASN1Sequence certs;

		public Data(byte[] messageBytes)
		{
			this.message = new DEROctetString(messageBytes);
		}

		public Data(ASN1OctetString message)
		{
			this.message = message;
		}

		public Data(DigestInfo messageImprint)
		{
			this.messageImprint = messageImprint;
		}

		public Data(TargetEtcChain cert)
		{
			this.certs = new DERSequence(cert);
		}

		public Data(TargetEtcChain[] certs)
		{
			this.certs = new DERSequence(certs);
		}

		private Data(ASN1Sequence certs)
		{
			this.certs = certs;
		}

		public static Data getInstance(object obj)
		{
			if (obj is Data)
			{
				return (Data)obj;
			}
			else if (obj is ASN1OctetString)
			{
				return new Data((ASN1OctetString)obj);
			}
			else if (obj is ASN1Sequence)
			{
				return new Data(DigestInfo.getInstance(obj));
			}
			else if (obj is ASN1TaggedObject)
			{
				return new Data(ASN1Sequence.getInstance((ASN1TaggedObject)obj, false));
			}
			throw new IllegalArgumentException("Unknown object submitted to getInstance: " + obj.GetType().getName());
		}

		public static Data getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(obj.getObject());
		}

		public override ASN1Primitive toASN1Primitive()
		{
			if (message != null)
			{
				return message.toASN1Primitive();
			}
			if (messageImprint != null)
			{
				return messageImprint.toASN1Primitive();
			}
			else
			{
				return new DERTaggedObject(false, 0, certs);
			}
		}

		public override string ToString()
		{
			if (message != null)
			{
				return "Data {\n" + message + "}\n";
			}
			if (messageImprint != null)
			{
				return "Data {\n" + messageImprint + "}\n";
			}
			else
			{
				return "Data {\n" + certs + "}\n";
			}
		}

		public virtual ASN1OctetString getMessage()
		{
			return message;
		}

		public virtual DigestInfo getMessageImprint()
		{
			return messageImprint;
		}

		public virtual TargetEtcChain[] getCerts()
		{
			if (certs == null)
			{
				return null;
			}

			TargetEtcChain[] tmp = new TargetEtcChain[certs.size()];

			for (int i = 0; i != tmp.Length; i++)
			{
				tmp[i] = TargetEtcChain.getInstance(certs.getObjectAt(i));
			}

			return tmp;
		}
	}

}