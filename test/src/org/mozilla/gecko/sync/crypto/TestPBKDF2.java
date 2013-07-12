package org.mozilla.gecko.sync.crypto;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;

import junit.framework.TestCase;

import org.mozilla.gecko.sync.Utils;

// Test vectors from
// <http://tools.ietf.org/html/draft-josefsson-pbkdf2-test-vectors-06>
public class TestPBKDF2 extends TestCase {

  public final void testPBKDF2SHA1A() throws GeneralSecurityException, UnsupportedEncodingException {
    String  p = "password";
    String  s = "salt";
    int dkLen = 20;

    checkPBKDFSHA1(p, s, 1, dkLen, "0c60c80f961f0e71f3a9b524af6012062fe037a6");
    checkPBKDFSHA1(p, s, 2, dkLen, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957");
    checkPBKDFSHA1(p, s, 4096, dkLen, "4b007901b765489abead49d926f721d065a429c1");
    
    // This test takes a long time. At least 8 minutes on my dual-core phone!
    // checkPBKDF2(p, s, 16777216, dkLen, "eefe3d61cd4da4e4e9945b3d6ba2158c2634e984");
  }

  public final void testPBKDF2SHA1B() throws GeneralSecurityException, UnsupportedEncodingException {
    String  p = "passwordPASSWORDpassword";
    String  s = "saltSALTsaltSALTsaltSALTsaltSALTsalt";
    int dkLen = 25;

    checkPBKDFSHA1(p, s, 4096, dkLen, "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038");
  }

  public final void testPBKDF2SHA256() throws UnsupportedEncodingException, GeneralSecurityException {
    String  p = "password";
    String  s = "salt";
    int dkLen = 32;
  
    checkPBKDFSHA256(p, s, 1, dkLen, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");
    checkPBKDFSHA256(p, s, 4096, dkLen, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a");
  }

  private void checkPBKDFSHA1(String p, String s, int c, int dkLen,
                              final String expectedStr)
                                                    throws GeneralSecurityException,
                                                    UnsupportedEncodingException {
    long start = System.currentTimeMillis();
    byte[] key = PBKDF2.pbkdf2SHA1SC(p.getBytes("US-ASCII"), s.getBytes("US-ASCII"), c, dkLen);
    long end = System.currentTimeMillis();
    System.err.println("SHA-1 " + c + " took " + (end - start) + "ms");
    assertExpectedBytes(expectedStr, key);
  }

  private void checkPBKDFSHA256(String p, String s, int c, int dkLen,
                                final String expectedStr)
                                                    throws GeneralSecurityException, UnsupportedEncodingException {
    long start = System.currentTimeMillis();
    byte[] key = PBKDF2.pbkdf2SHA256SC(p.getBytes("US-ASCII"), s.getBytes("US-ASCII"), c, dkLen);
    long end = System.currentTimeMillis();
    System.err.println("SHA-256 " + c + " took " + (end - start) + "ms");
    assertExpectedBytes(expectedStr, key);
  }

  private void assertExpectedBytes(final String expectedStr, byte[] key) {
    byte[] expected = Utils.hex2Byte(expectedStr);

    assertEquals(expected.length, key.length);
    for (int i = 0; i < key.length; i++) {
      assertEquals(expected[i], key[i]);
    }
  }
}
