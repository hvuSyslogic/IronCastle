using System;

namespace org.bouncycastle.dvcs
{

	using DVCSRequestInformation = org.bouncycastle.asn1.dvcs.DVCSRequestInformation;
	using DVCSTime = org.bouncycastle.asn1.dvcs.DVCSTime;
	using GeneralNames = org.bouncycastle.asn1.x509.GeneralNames;
	using PolicyInformation = org.bouncycastle.asn1.x509.PolicyInformation;
	using TimeStampToken = org.bouncycastle.tsp.TimeStampToken;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// Information piece of DVCS requests.
	/// It is common for all types of DVCS requests.
	/// </summary>
	public class DVCSRequestInfo
	{
		private DVCSRequestInformation data;

		/// <summary>
		/// Constructs DVCRequestInfo from byte array (DER encoded DVCSRequestInformation).
		/// </summary>
		/// <param name="in"> a byte array holding the encoding of a DVCSRequestInformation structure. </param>
		public DVCSRequestInfo(byte[] @in) : this(DVCSRequestInformation.getInstance(@in))
		{
		}

		/// <summary>
		/// Constructs DVCRequestInfo from DVCSRequestInformation ASN.1 structure.
		/// </summary>
		/// <param name="data"> a DVCSRequestInformation to populate this object with. </param>
		public DVCSRequestInfo(DVCSRequestInformation data)
		{
			this.data = data;
		}

		/// <summary>
		/// Converts to corresponding ASN.1 structure (DVCSRequestInformation).
		/// </summary>
		/// <returns> a DVCSRequestInformation object. </returns>
		public virtual DVCSRequestInformation toASN1Structure()
		{
			return data;
		}

		//
		// DVCRequestInfo selector interface
		//

		/// <summary>
		/// Get DVCS version of request.
		/// </summary>
		/// <returns> the version number of the request. </returns>
		public virtual int getVersion()
		{
			return data.getVersion();
		}

		/// <summary>
		/// Get requested service type.
		/// </summary>
		/// <returns> one of CPD, VSD, VPKC, CCPD (see constants). </returns>
		public virtual int getServiceType()
		{
			return data.getService().getValue().intValue();
		}

		/// <summary>
		/// Get nonce if it is set.
		/// Note: this field can be set (if not present) or extended (if present) by DVCS.
		/// </summary>
		/// <returns> nonce value, or null if it is not set. </returns>
		public virtual BigInteger getNonce()
		{
			return data.getNonce();
		}

		/// <summary>
		/// Get request generation time if it is set.
		/// </summary>
		/// <returns> time of request, or null if it is not set. </returns>
		/// <exception cref="DVCSParsingException"> if a request time is present but cannot be extracted. </exception>
		public virtual DateTime getRequestTime()
		{
			DVCSTime time = data.getRequestTime();

			if (time == null)
			{
				return null;
			}

			try
			{
				if (time.getGenTime() != null)
				{
					return time.getGenTime().getDate();
				}
				else
				{
					TimeStampToken token = new TimeStampToken(time.getTimeStampToken());

					return token.getTimeStampInfo().getGenTime();
				}
			}
			catch (Exception e)
			{
				throw new DVCSParsingException("unable to extract time: " + e.Message, e);
			}
		}

		/// <summary>
		/// Get names of requesting entity, if set.
		/// </summary>
		/// <returns> the requesting entity, or null. </returns>
		public virtual GeneralNames getRequester()
		{
			return data.getRequester();
		}

		/// <summary>
		/// Get policy, under which the validation is requested.
		/// </summary>
		/// <returns> policy identifier or null, if any policy is acceptable. </returns>
		public virtual PolicyInformation getRequestPolicy()
		{
			if (data.getRequestPolicy() != null)
			{
				return data.getRequestPolicy();
			}
			return null;
		}

		/// <summary>
		/// Get names of DVCS servers.
		/// Note: this field can be set by DVCS.
		/// </summary>
		/// <returns> the DVCS names object, or null if not set. </returns>
		public virtual GeneralNames getDVCSNames()
		{
			return data.getDVCS();
		}

		/// <summary>
		/// Get data locations, where the copy of request Data can be obtained.
		/// Note: the exact meaning of field is up to applications.
		/// Note: this field can be set by DVCS.
		/// </summary>
		/// <returns> the DVCS dataLocations object, or null if not set. </returns>
		public virtual GeneralNames getDataLocations()
		{
			return data.getDataLocations();
		}

		/// <summary>
		/// Compares two DVCRequestInfo structures: one from DVCRequest, and one from DVCResponse.
		/// This function implements RFC 3029, 9.1 checks of reqInfo.
		/// </summary>
		/// <param name="requestInfo">  - DVCRequestInfo of DVCRequest </param>
		/// <param name="responseInfo"> - DVCRequestInfo of DVCResponse </param>
		/// <returns> true if server's requestInfo matches client's requestInfo </returns>
		public static bool validate(DVCSRequestInfo requestInfo, DVCSRequestInfo responseInfo)
		{
			// RFC 3029, 9.1
			// The DVCS MAY modify the fields:
			// 'dvcs', 'requester', 'dataLocations', and 'nonce' of the ReqInfo structure.

			DVCSRequestInformation clientInfo = requestInfo.data;
			DVCSRequestInformation serverInfo = responseInfo.data;

			if (clientInfo.getVersion() != serverInfo.getVersion())
			{
				return false;
			}
			if (!clientEqualsServer(clientInfo.getService(), serverInfo.getService()))
			{
				return false;
			}
			if (!clientEqualsServer(clientInfo.getRequestTime(), serverInfo.getRequestTime()))
			{
				return false;
			}
			if (!clientEqualsServer(clientInfo.getRequestPolicy(), serverInfo.getRequestPolicy()))
			{
				return false;
			}
			if (!clientEqualsServer(clientInfo.getExtensions(), serverInfo.getExtensions()))
			{
				return false;
			}

			// RFC 3029, 9.1. The only modification allowed to a 'nonce'
			// is the inclusion of a new field if it was not present,
			// or to concatenate other data to the end (right) of an existing value.

			if (clientInfo.getNonce() != null)
			{
				if (serverInfo.getNonce() == null)
				{
					return false;
				}
				byte[] clientNonce = clientInfo.getNonce().toByteArray();
				byte[] serverNonce = serverInfo.getNonce().toByteArray();
				if (serverNonce.Length < clientNonce.Length)
				{
					return false;
				}
				if (!Arrays.areEqual(clientNonce, Arrays.copyOfRange(serverNonce, 0, clientNonce.Length)))
				{
					return false;
				}
			}

			return true;
		}

		// null-protected compare of any two objects
		private static bool clientEqualsServer(object client, object server)
		{
			return (client == null && server == null) || (client != null && client.Equals(server));
		}
	}


}