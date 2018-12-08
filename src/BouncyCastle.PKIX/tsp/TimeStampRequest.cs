namespace org.bouncycastle.tsp
{

	using ASN1InputStream = org.bouncycastle.asn1.ASN1InputStream;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using PKIFailureInfo = org.bouncycastle.asn1.cmp.PKIFailureInfo;
	using TimeStampReq = org.bouncycastle.asn1.tsp.TimeStampReq;
	using Extension = org.bouncycastle.asn1.x509.Extension;
	using Extensions = org.bouncycastle.asn1.x509.Extensions;

	/// <summary>
	/// Base class for an RFC 3161 Time Stamp Request.
	/// </summary>
	public class TimeStampRequest
	{
		private static Set EMPTY_SET = Collections.unmodifiableSet(new HashSet());

		private TimeStampReq req;
		private Extensions extensions;

		public TimeStampRequest(TimeStampReq req)
		{
			this.req = req;
			this.extensions = req.getExtensions();
		}

		/// <summary>
		/// Create a TimeStampRequest from the past in byte array.
		/// </summary>
		/// <param name="req"> byte array containing the request. </param>
		/// <exception cref="IOException"> if the request is malformed. </exception>
		public TimeStampRequest(byte[] req) : this(new ByteArrayInputStream(req))
		{
		}

		/// <summary>
		/// Create a TimeStampRequest from the past in input stream.
		/// </summary>
		/// <param name="in"> input stream containing the request. </param>
		/// <exception cref="IOException"> if the request is malformed. </exception>
		public TimeStampRequest(InputStream @in) : this(loadRequest(@in))
		{
		}

		private static TimeStampReq loadRequest(InputStream @in)
		{
			try
			{
				return TimeStampReq.getInstance((new ASN1InputStream(@in)).readObject());
			}
			catch (ClassCastException e)
			{
				throw new IOException("malformed request: " + e);
			}
			catch (IllegalArgumentException e)
			{
				throw new IOException("malformed request: " + e);
			}
		}

		public virtual int getVersion()
		{
			return req.getVersion().getValue().intValue();
		}

		public virtual ASN1ObjectIdentifier getMessageImprintAlgOID()
		{
			return req.getMessageImprint().getHashAlgorithm().getAlgorithm();
		}

		public virtual byte[] getMessageImprintDigest()
		{
			return req.getMessageImprint().getHashedMessage();
		}

		public virtual ASN1ObjectIdentifier getReqPolicy()
		{
			if (req.getReqPolicy() != null)
			{
				return req.getReqPolicy();
			}
			else
			{
				return null;
			}
		}

		public virtual BigInteger getNonce()
		{
			if (req.getNonce() != null)
			{
				return req.getNonce().getValue();
			}
			else
			{
				return null;
			}
		}

		public virtual bool getCertReq()
		{
			if (req.getCertReq() != null)
			{
				return req.getCertReq().isTrue();
			}
			else
			{
				return false;
			}
		}

		/// <summary>
		/// Validate the timestamp request, checking the digest to see if it is of an
		/// accepted type and whether it is of the correct length for the algorithm specified.
		/// </summary>
		/// <param name="algorithms"> a set of OIDs giving accepted algorithms. </param>
		/// <param name="policies"> if non-null a set of policies OIDs we are willing to sign under. </param>
		/// <param name="extensions"> if non-null a set of extensions OIDs we are willing to accept. </param>
		/// <exception cref="TSPException"> if the request is invalid, or processing fails. </exception>
		public virtual void validate(Set algorithms, Set policies, Set extensions)
		{
			algorithms = convert(algorithms);
			policies = convert(policies);
			extensions = convert(extensions);

			if (!algorithms.contains(this.getMessageImprintAlgOID()))
			{
				throw new TSPValidationException("request contains unknown algorithm", PKIFailureInfo.badAlg);
			}

			if (policies != null && this.getReqPolicy() != null && !policies.contains(this.getReqPolicy()))
			{
				throw new TSPValidationException("request contains unknown policy", PKIFailureInfo.unacceptedPolicy);
			}

			if (this.getExtensions() != null && extensions != null)
			{
				Enumeration en = this.getExtensions().oids();
				while (en.hasMoreElements())
				{
					ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)en.nextElement();
					if (!extensions.contains(oid))
					{
						throw new TSPValidationException("request contains unknown extension", PKIFailureInfo.unacceptedExtension);
					}
				}
			}

			int digestLength = TSPUtil.getDigestLength(this.getMessageImprintAlgOID().getId());

			if (digestLength != this.getMessageImprintDigest().Length)
			{
				throw new TSPValidationException("imprint digest the wrong length", PKIFailureInfo.badDataFormat);
			}
		}

	   /// <summary>
	   /// return the ASN.1 encoded representation of this object. </summary>
	   /// <returns> the default ASN,1 byte encoding for the object. </returns>
		public virtual byte[] getEncoded()
		{
			return req.getEncoded();
		}

		public virtual Extensions getExtensions()
		{
			return extensions;
		}

		public virtual bool hasExtensions()
		{
			return extensions != null;
		}

		public virtual Extension getExtension(ASN1ObjectIdentifier oid)
		{
			if (extensions != null)
			{
				return extensions.getExtension(oid);
			}

			return null;
		}

		public virtual List getExtensionOIDs()
		{
			return TSPUtil.getExtensionOIDs(extensions);
		}

		/// <summary>
		/// Returns a set of ASN1ObjectIdentifiers giving the non-critical extensions. </summary>
		/// <returns> a set of ASN1ObjectIdentifiers. </returns>
		public virtual Set getNonCriticalExtensionOIDs()
		{
			if (extensions == null)
			{
				return EMPTY_SET;
			}

			return Collections.unmodifiableSet(new HashSet(Arrays.asList(extensions.getNonCriticalExtensionOIDs())));
		}

		/// <summary>
		/// Returns a set of ASN1ObjectIdentifiers giving the critical extensions. </summary>
		/// <returns> a set of ASN1ObjectIdentifiers. </returns>
		public virtual Set getCriticalExtensionOIDs()
		{
			if (extensions == null)
			{
				return EMPTY_SET;
			}

			return Collections.unmodifiableSet(new HashSet(Arrays.asList(extensions.getCriticalExtensionOIDs())));
		}

		private Set convert(Set orig)
		{
			if (orig == null)
			{
				return orig;
			}

			Set con = new HashSet(orig.size());

			for (Iterator it = orig.iterator(); it.hasNext();)
			{
				object o = it.next();

				if (o is string)
				{
					con.add(new ASN1ObjectIdentifier((string)o));
				}
				else
				{
					con.add(o);
				}
			}

			return con;
		}
	}

}