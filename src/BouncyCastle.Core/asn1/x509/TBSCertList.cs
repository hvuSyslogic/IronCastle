using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.x509
{

	using X500Name = org.bouncycastle.asn1.x500.X500Name;

	/// <summary>
	/// PKIX RFC-2459 - TBSCertList object.
	/// <pre>
	/// TBSCertList  ::=  SEQUENCE  {
	///      version                 Version OPTIONAL,
	///                                   -- if present, shall be v2
	///      signature               AlgorithmIdentifier,
	///      issuer                  Name,
	///      thisUpdate              Time,
	///      nextUpdate              Time OPTIONAL,
	///      revokedCertificates     SEQUENCE OF SEQUENCE  {
	///           userCertificate         CertificateSerialNumber,
	///           revocationDate          Time,
	///           crlEntryExtensions      Extensions OPTIONAL
	///                                         -- if present, shall be v2
	///                                }  OPTIONAL,
	///      crlExtensions           [0]  EXPLICIT Extensions OPTIONAL
	///                                         -- if present, shall be v2
	///                                }
	/// </pre>
	/// </summary>
	public class TBSCertList : ASN1Object
	{
		public class CRLEntry : ASN1Object
		{
			internal ASN1Sequence seq;

			internal Extensions crlEntryExtensions;

			public CRLEntry(ASN1Sequence seq)
			{
				if (seq.size() < 2 || seq.size() > 3)
				{
					throw new IllegalArgumentException("Bad sequence size: " + seq.size());
				}

				this.seq = seq;
			}

			public static CRLEntry getInstance(object o)
			{
				if (o is CRLEntry)
				{
					return ((CRLEntry)o);
				}
				else if (o != null)
				{
					return new CRLEntry(ASN1Sequence.getInstance(o));
				}

				return null;
			}

			public virtual ASN1Integer getUserCertificate()
			{
				return ASN1Integer.getInstance(seq.getObjectAt(0));
			}

			public virtual Time getRevocationDate()
			{
				return Time.getInstance(seq.getObjectAt(1));
			}

			public virtual Extensions getExtensions()
			{
				if (crlEntryExtensions == null && seq.size() == 3)
				{
					crlEntryExtensions = Extensions.getInstance(seq.getObjectAt(2));
				}

				return crlEntryExtensions;
			}

			public override ASN1Primitive toASN1Primitive()
			{
				return seq;
			}

			public virtual bool hasExtensions()
			{
				return seq.size() == 3;
			}
		}

		public class RevokedCertificatesEnumeration : Enumeration
		{
			private readonly TBSCertList outerInstance;

			internal readonly Enumeration en;

			public RevokedCertificatesEnumeration(TBSCertList outerInstance, Enumeration en)
			{
				this.outerInstance = outerInstance;
				this.en = en;
			}

			public virtual bool hasMoreElements()
			{
				return en.hasMoreElements();
			}

			public virtual object nextElement()
			{
				return CRLEntry.getInstance(en.nextElement());
			}
		}

		public class EmptyEnumeration : Enumeration
		{
			private readonly TBSCertList outerInstance;

			public EmptyEnumeration(TBSCertList outerInstance)
			{
				this.outerInstance = outerInstance;
			}

			public virtual bool hasMoreElements()
			{
				return false;
			}

			public virtual object nextElement()
			{
				throw new NoSuchElementException("Empty Enumeration");
			}
		}

		internal ASN1Integer version;
		internal AlgorithmIdentifier signature;
		internal X500Name issuer;
		internal Time thisUpdate;
		internal Time nextUpdate;
		internal ASN1Sequence revokedCertificates;
		internal Extensions crlExtensions;

		public static TBSCertList getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		public static TBSCertList getInstance(object obj)
		{
			if (obj is TBSCertList)
			{
				return (TBSCertList)obj;
			}
			else if (obj != null)
			{
				return new TBSCertList(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public TBSCertList(ASN1Sequence seq)
		{
			if (seq.size() < 3 || seq.size() > 7)
			{
				throw new IllegalArgumentException("Bad sequence size: " + seq.size());
			}

			int seqPos = 0;

			if (seq.getObjectAt(seqPos) is ASN1Integer)
			{
				version = ASN1Integer.getInstance(seq.getObjectAt(seqPos++));
			}
			else
			{
				version = null; // version is optional
			}

			signature = AlgorithmIdentifier.getInstance(seq.getObjectAt(seqPos++));
			issuer = X500Name.getInstance(seq.getObjectAt(seqPos++));
			thisUpdate = Time.getInstance(seq.getObjectAt(seqPos++));

			if (seqPos < seq.size() && (seq.getObjectAt(seqPos) is ASN1UTCTime || seq.getObjectAt(seqPos) is ASN1GeneralizedTime || seq.getObjectAt(seqPos) is Time))
			{
				nextUpdate = Time.getInstance(seq.getObjectAt(seqPos++));
			}

			if (seqPos < seq.size() && !(seq.getObjectAt(seqPos) is ASN1TaggedObject))
			{
				revokedCertificates = ASN1Sequence.getInstance(seq.getObjectAt(seqPos++));
			}

			if (seqPos < seq.size() && seq.getObjectAt(seqPos) is ASN1TaggedObject)
			{
				crlExtensions = Extensions.getInstance(ASN1Sequence.getInstance((ASN1TaggedObject)seq.getObjectAt(seqPos), true));
			}
		}

		public virtual int getVersionNumber()
		{
			if (version == null)
			{
				return 1;
			}
			return version.getValue().intValue() + 1;
		}

		public virtual ASN1Integer getVersion()
		{
			return version;
		}

		public virtual AlgorithmIdentifier getSignature()
		{
			return signature;
		}

		public virtual X500Name getIssuer()
		{
			return issuer;
		}

		public virtual Time getThisUpdate()
		{
			return thisUpdate;
		}

		public virtual Time getNextUpdate()
		{
			return nextUpdate;
		}

		public virtual CRLEntry[] getRevokedCertificates()
		{
			if (revokedCertificates == null)
			{
				return new CRLEntry[0];
			}

			CRLEntry[] entries = new CRLEntry[revokedCertificates.size()];

			for (int i = 0; i < entries.Length; i++)
			{
				entries[i] = CRLEntry.getInstance(revokedCertificates.getObjectAt(i));
			}

			return entries;
		}

		public virtual Enumeration getRevokedCertificateEnumeration()
		{
			if (revokedCertificates == null)
			{
				return new EmptyEnumeration(this);
			}

			return new RevokedCertificatesEnumeration(this, revokedCertificates.getObjects());
		}

		public virtual Extensions getExtensions()
		{
			return crlExtensions;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			if (version != null)
			{
				v.add(version);
			}
			v.add(signature);
			v.add(issuer);

			v.add(thisUpdate);
			if (nextUpdate != null)
			{
				v.add(nextUpdate);
			}

			// Add CRLEntries if they exist
			if (revokedCertificates != null)
			{
				v.add(revokedCertificates);
			}

			if (crlExtensions != null)
			{
				v.add(new DERTaggedObject(0, crlExtensions));
			}

			return new DERSequence(v);
		}
	}

}