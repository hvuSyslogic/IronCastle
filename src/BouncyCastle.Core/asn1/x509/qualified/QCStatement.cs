using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.x509.qualified
{


	/// <summary>
	/// The QCStatement object.
	/// <pre>
	/// QCStatement ::= SEQUENCE {
	///   statementId        OBJECT IDENTIFIER,
	///   statementInfo      ANY DEFINED BY statementId OPTIONAL} 
	/// </pre>
	/// </summary>

	public class QCStatement : ASN1Object, ETSIQCObjectIdentifiers, RFC3739QCObjectIdentifiers
	{
		internal ASN1ObjectIdentifier qcStatementId;
		internal ASN1Encodable qcStatementInfo;

		public static QCStatement getInstance(object obj)
		{
			if (obj is QCStatement)
			{
				return (QCStatement)obj;
			}
			if (obj != null)
			{
				return new QCStatement(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		private QCStatement(ASN1Sequence seq)
		{
			Enumeration e = seq.getObjects();

			// qcStatementId
			qcStatementId = ASN1ObjectIdentifier.getInstance(e.nextElement());
			// qcstatementInfo
			if (e.hasMoreElements())
			{
				qcStatementInfo = (ASN1Encodable) e.nextElement();
			}
		}

		public QCStatement(ASN1ObjectIdentifier qcStatementId)
		{
			this.qcStatementId = qcStatementId;
			this.qcStatementInfo = null;
		}

		public QCStatement(ASN1ObjectIdentifier qcStatementId, ASN1Encodable qcStatementInfo)
		{
			this.qcStatementId = qcStatementId;
			this.qcStatementInfo = qcStatementInfo;
		}

		public virtual ASN1ObjectIdentifier getStatementId()
		{
			return qcStatementId;
		}

		public virtual ASN1Encodable getStatementInfo()
		{
			return qcStatementInfo;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector seq = new ASN1EncodableVector();
			seq.add(qcStatementId);

			if (qcStatementInfo != null)
			{
				seq.add(qcStatementInfo);
			}

			return new DERSequence(seq);
		}
	}

}