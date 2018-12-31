﻿using org.bouncycastle.asn1.x509;

namespace org.bouncycastle.asn1.ocsp
{
		
	public class SingleResponse : ASN1Object
	{
		private CertID certID;
		private CertStatus certStatus;
		private ASN1GeneralizedTime thisUpdate;
		private ASN1GeneralizedTime nextUpdate;
		private Extensions singleExtensions;

		/// @deprecated use method taking ASN1GeneralizedTime and Extensions 
		/// <param name="certID"> </param>
		/// <param name="certStatus"> </param>
		/// <param name="thisUpdate"> </param>
		/// <param name="nextUpdate"> </param>
		/// <param name="singleExtensions"> </param>
		public SingleResponse(CertID certID, CertStatus certStatus, ASN1GeneralizedTime thisUpdate, ASN1GeneralizedTime nextUpdate, X509Extensions singleExtensions) : this(certID, certStatus, thisUpdate, nextUpdate, Extensions.getInstance(singleExtensions))
		{
		}

		public SingleResponse(CertID certID, CertStatus certStatus, ASN1GeneralizedTime thisUpdate, ASN1GeneralizedTime nextUpdate, Extensions singleExtensions)
		{
			this.certID = certID;
			this.certStatus = certStatus;
			this.thisUpdate = thisUpdate;
			this.nextUpdate = nextUpdate;
			this.singleExtensions = singleExtensions;
		}

		private SingleResponse(ASN1Sequence seq)
		{
			this.certID = CertID.getInstance(seq.getObjectAt(0));
			this.certStatus = CertStatus.getInstance(seq.getObjectAt(1));
			this.thisUpdate = ASN1GeneralizedTime.getInstance(seq.getObjectAt(2));

			if (seq.size() > 4)
			{
				this.nextUpdate = ASN1GeneralizedTime.getInstance((ASN1TaggedObject)seq.getObjectAt(3), true);
				this.singleExtensions = Extensions.getInstance((ASN1TaggedObject)seq.getObjectAt(4), true);
			}
			else if (seq.size() > 3)
			{
				ASN1TaggedObject o = (ASN1TaggedObject)seq.getObjectAt(3);

				if (o.getTagNo() == 0)
				{
					this.nextUpdate = ASN1GeneralizedTime.getInstance(o, true);
				}
				else
				{
					this.singleExtensions = Extensions.getInstance(o, true);
				}
			}
		}

		public static SingleResponse getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		public static SingleResponse getInstance(object obj)
		{
			if (obj is SingleResponse)
			{
				return (SingleResponse)obj;
			}
			else if (obj != null)
			{
				return new SingleResponse(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public virtual CertID getCertID()
		{
			return certID;
		}

		public virtual CertStatus getCertStatus()
		{
			return certStatus;
		}

		public virtual ASN1GeneralizedTime getThisUpdate()
		{
			return thisUpdate;
		}

		public virtual ASN1GeneralizedTime getNextUpdate()
		{
			return nextUpdate;
		}

		public virtual Extensions getSingleExtensions()
		{
			return singleExtensions;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// <pre>
		///  SingleResponse ::= SEQUENCE {
		///          certID                       CertID,
		///          certStatus                   CertStatus,
		///          thisUpdate                   GeneralizedTime,
		///          nextUpdate         [0]       EXPLICIT GeneralizedTime OPTIONAL,
		///          singleExtensions   [1]       EXPLICIT Extensions OPTIONAL }
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(certID);
			v.add(certStatus);
			v.add(thisUpdate);

			if (nextUpdate != null)
			{
				v.add(new DERTaggedObject(true, 0, nextUpdate));
			}

			if (singleExtensions != null)
			{
				v.add(new DERTaggedObject(true, 1, singleExtensions));
			}

			return new DERSequence(v);
		}
	}

}