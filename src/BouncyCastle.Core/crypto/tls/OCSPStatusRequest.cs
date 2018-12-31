using System.IO;
using org.bouncycastle.asn1;
using org.bouncycastle.asn1.ocsp;
using org.bouncycastle.asn1.x509;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.Port.java.util;
using org.bouncycastle.util.io;

namespace org.bouncycastle.crypto.tls
{

				
	/// <summary>
	/// RFC 3546 3.6
	/// </summary>
	public class OCSPStatusRequest
	{
		protected internal Vector responderIDList;
		protected internal Extensions requestExtensions;

		/// <param name="responderIDList">
		///            a <seealso cref="Vector"/> of <seealso cref="ResponderID"/>, specifying the list of trusted OCSP
		///            responders. An empty list has the special meaning that the responders are
		///            implicitly known to the server - e.g., by prior arrangement. </param>
		/// <param name="requestExtensions">
		///            OCSP request extensions. A null value means that there are no extensions. </param>
		public OCSPStatusRequest(Vector responderIDList, Extensions requestExtensions)
		{
			this.responderIDList = responderIDList;
			this.requestExtensions = requestExtensions;
		}

		/// <returns> a <seealso cref="Vector"/> of <seealso cref="ResponderID"/> </returns>
		public virtual Vector getResponderIDList()
		{
			return responderIDList;
		}

		/// <returns> OCSP request extensions </returns>
		public virtual Extensions getRequestExtensions()
		{
			return requestExtensions;
		}

		/// <summary>
		/// Encode this <seealso cref="OCSPStatusRequest"/> to an <seealso cref="OutputStream"/>.
		/// </summary>
		/// <param name="output">
		///            the <seealso cref="OutputStream"/> to encode to. </param>
		/// <exception cref="IOException"> </exception>
		public virtual void encode(OutputStream output)
		{
			if (responderIDList == null || responderIDList.isEmpty())
			{
				TlsUtils.writeUint16(0, output);
			}
			else
			{
				ByteArrayOutputStream buf = new ByteArrayOutputStream();
				for (int i = 0; i < responderIDList.size(); ++i)
				{
					ResponderID responderID = (ResponderID) responderIDList.elementAt(i);
					byte[] derEncoding = responderID.getEncoded(ASN1Encoding_Fields.DER);
					TlsUtils.writeOpaque16(derEncoding, buf);
				}
				TlsUtils.checkUint16(buf.size());
				TlsUtils.writeUint16(buf.size(), output);
				Streams.writeBufTo(buf, output);
			}

			if (requestExtensions == null)
			{
				TlsUtils.writeUint16(0, output);
			}
			else
			{
				byte[] derEncoding = requestExtensions.getEncoded(ASN1Encoding_Fields.DER);
				TlsUtils.checkUint16(derEncoding.Length);
				TlsUtils.writeUint16(derEncoding.Length, output);
				output.write(derEncoding);
			}
		}

		/// <summary>
		/// Parse an <seealso cref="OCSPStatusRequest"/> from an <seealso cref="InputStream"/>.
		/// </summary>
		/// <param name="input">
		///            the <seealso cref="InputStream"/> to parse from. </param>
		/// <returns> an <seealso cref="OCSPStatusRequest"/> object. </returns>
		/// <exception cref="IOException"> </exception>
		public static OCSPStatusRequest parse(InputStream input)
		{
			Vector responderIDList = new Vector();
			{
				int length = TlsUtils.readUint16(input);
				if (length > 0)
				{
					byte[] data = TlsUtils.readFully(length, input);
					ByteArrayInputStream buf = new ByteArrayInputStream(data);
					do
					{
						byte[] derEncoding = TlsUtils.readOpaque16(buf);
						ResponderID responderID = ResponderID.getInstance(TlsUtils.readDERObject(derEncoding));
						responderIDList.addElement(responderID);
					} while (buf.available() > 0);
				}
			}

			Extensions requestExtensions = null;
			{
				int length = TlsUtils.readUint16(input);
				if (length > 0)
				{
					byte[] derEncoding = TlsUtils.readFully(length, input);
					requestExtensions = Extensions.getInstance(TlsUtils.readDERObject(derEncoding));
				}
			}

			return new OCSPStatusRequest(responderIDList, requestExtensions);
		}
	}

}