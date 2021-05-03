package crypto;

import crypto.pbe.Pbe;
import crypto.signature.DigitalSignature;
import crypto.symmetric.Aes;
import crypto.symmetric.Gcm;
import crypto.verification.Hash;
import crypto.verification.Macs;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class CryptoManagerTest {
  Aes coverageAes = new Aes();
  Gcm coverageGcm = new Gcm();
  DigitalSignature coverageDigitalSignature = new DigitalSignature();
  Hash hashCoverage = new Hash();
  Macs macCoverage = new Macs();
  Pbe pbe = new Pbe();

  @Test
  void encryptAesCbcWithoutPassword() {

    CryptoManager cm = new CryptoManager(
            "000102030405060708090a0b0c0d0e0f",
            "AES",
            "CBC",
            "NoPadding",
            "SHA-256",
            256,
            "");
    try {
      String[] encrypt = cm.encrypt();
      // key
      assertNotEquals(null, encrypt[0]);
      // encrypted message
      assertNotEquals(null, encrypt[1]);
      // iv
      assertNotEquals(null, encrypt[2]);
      // hash
      assertNotEquals(null, encrypt[3]);
      // macKey
      assertEquals(null, encrypt[4]);
      // signature
      assertNotEquals(null, encrypt[5]);
      // signaturekey
      assertNotEquals(null, encrypt[6]);
      // salt
      assertEquals(null, encrypt[7]);
    } catch (Exception e) {
      fail();
      e.printStackTrace();
    }

  }

  @Test
  void encryptAesGcmScryptWithPassword() {

    CryptoManager cm = new CryptoManager(
            "000102030405060708090a0b0c0d0e0f",
            "AES256, GCM, SCrypt",
            "",
            "NoPadding",
            "SHA-256",
            0,
            "test123");
    try {
      String[] encrypt = cm.encrypt();
      // key
      assertEquals(null, encrypt[0]);
      // encrypted message
      assertNotEquals(null, encrypt[1]);
      // iv
      assertNotEquals(null, encrypt[2]);
      // hash
      assertNotEquals(null, encrypt[3]);
      // macKey
      assertEquals(null, encrypt[4]);
      // signature
      assertNotEquals(null, encrypt[5]);
      // signaturekey
      assertNotEquals(null, encrypt[6]);
      // salt
      assertNotEquals(null, encrypt[7]);
    } catch (Exception e) {
      e.printStackTrace();
      fail();
    }

  }

  @Test
  void encryptPBEWithSHA256And128BitAESCBCBC() {
    CryptoManager cm = new CryptoManager(
            "000102030405060708090a0b0c0d0e0f",
            "PBEWithSHA256And128BitAES-CBC-BC",
            "",
            "",
            "SHA-256",
            0,
            "teeeeeeeeeeeeeeeeeeeeeeeeeeest");
    try {
      String[] encrypt = cm.encrypt();
      // key
      assertEquals(null, encrypt[0]);
      // encrypted message
      assertNotEquals(null, encrypt[1]);
      // iv
      assertEquals(null, encrypt[2]);
      // hash
      assertNotEquals(null, encrypt[3]);
      // macKey
      assertEquals(null, encrypt[4]);
      // signature
      assertNotEquals(null, encrypt[5]);
      // signaturekey
      assertNotEquals(null, encrypt[6]);
      // salt
      assertNotEquals(null, encrypt[7]);
    } catch (Exception e) {
      fail();
      e.printStackTrace();
    }

  }

  @Test
  void encryptPBEWithSHAAnd40BitRC4() {
    CryptoManager cm = new CryptoManager(
            "000102030405060708090a0b0c0d0e0f",
            "PBEWithSHAAnd40BitRC4",
            "",
            "",
            "SHA-256",
            0,
            "testing it");
    try {
      String[] encrypt = cm.encrypt();
      // key
      assertEquals(null, encrypt[0]);
      // encrypted message
      assertNotEquals(null, encrypt[1]);
      // iv
      assertEquals(null, encrypt[2]);
      // hash
      assertNotEquals(null, encrypt[3]);
      // macKey
      assertEquals(null, encrypt[4]);
      // signature
      assertNotEquals(null, encrypt[5]);
      // signaturekey
      assertNotEquals(null, encrypt[6]);
      // salt
      assertNotEquals(null, encrypt[7]);
    } catch (Exception e) {
      fail();
      e.printStackTrace();
    }

  }

  @Test
  void encryptAesCbcWithoutPasswordWithAESCMAC() {
    CryptoManager cm = new CryptoManager(
            "000102030405060708090a0b0c0d0e0f",
            "AES",
            "CBC",
            "PKCS5Padding",
            "AESCMAC",
            256,
            "");
    try {
      String[] encrypt = cm.encrypt();
      // key
      assertNotEquals(null, encrypt[0]);
      // encrypted message
      assertNotEquals(null, encrypt[1]);
      // iv
      assertNotEquals(null, encrypt[2]);
      // hash
      assertNotEquals(null, encrypt[3]);
      // macKey
      assertNotEquals(null, encrypt[4]);
      // signature
      assertNotEquals(null, encrypt[5]);
      // signaturekey
      assertNotEquals(null, encrypt[6]);
      // salt
      assertEquals(null, encrypt[7]);
    } catch (Exception e) {
      fail();
      e.printStackTrace();
    }

  }

  @Test
  void encryptAesCbcWithoutPasswordWithHMac() {
    CryptoManager cm = new CryptoManager(
            "000102030405060708090a0b0c0d0e",
            "AES",
            "CBC",
            "PKCS5Padding",
            "HmacSHA256",
            256,
            "");
    try {
      String[] encrypt = cm.encrypt();
      // key
      assertNotEquals(null, encrypt[0]);
      // encrypted message
      assertNotEquals(null, encrypt[1]);
      // iv
      assertNotEquals(null, encrypt[2]);
      // hash
      assertNotEquals(null, encrypt[3]);
      // macKey
      assertNotEquals(null, encrypt[4]);
      // signature
      assertNotEquals(null, encrypt[5]);
      // signaturekey
      assertNotEquals(null, encrypt[6]);
      // salt
      assertEquals(null, encrypt[7]);
    } catch (Exception e) {
      fail();
      e.printStackTrace();
    }

  }

  @Test
  void encryptAesEcbWithoutPassword() {
    CryptoManager cm = new CryptoManager(
            "000102030405060708090a0b0c0d0e0f",
            "AES",
            "ECB",
            "PKCS5Padding",
            "SHA-256",
            256,
            "");
    try {
      String[] encrypt = cm.encrypt();

      // key
      assertNotEquals(null, encrypt[0]);
      // encrypted message
      assertNotEquals(null, encrypt[1]);
      // iv
      assertEquals(null, encrypt[2]);
      // hash
      assertNotEquals(null, encrypt[3]);
      // macKey
      assertEquals(null, encrypt[4]);
      // signature
      assertNotEquals(null, encrypt[5]);
      // signaturekey
      assertNotEquals(null, encrypt[6]);
      // salt
      assertEquals(null, encrypt[7]);
    } catch (Exception e) {
      e.printStackTrace();
      fail();
    }
  }

  @Test
  void encryptAesGcmWithoutPassword() {
    String[] keys = {"", ""};
    CryptoManager cm = new CryptoManager(
            "000102030405060708090a0b0c0d0e0f",
            "AES",
            "GCM",
            "NoPadding",
            "SHA-256",
            256,
            "");
    try {
      String[] encrypt = cm.encrypt();
      // key
      assertNotEquals(null, encrypt[0]);
      // encrypted message
      assertNotEquals(null, encrypt[1]);
      // iv
      assertNotEquals(null, encrypt[2]);
      // hash
      assertNotEquals(null, encrypt[3]);
      // macKey
      assertEquals(null, encrypt[4]);
      // signature
      assertNotEquals(null, encrypt[5]);
      // signaturekey
      assertNotEquals(null, encrypt[6]);
      // salt
      assertEquals(null, encrypt[7]);
    } catch (Exception e) {
      fail();
      e.printStackTrace();
    }

  }

  @Test
  void encryptAesCcmWithoutPassword() {
    CryptoManager cm = new CryptoManager(
            "000102030405060708090a0b0c0d0e0f",
            "AES",
            "CCM",
            "NoPadding",
            "SHA-256",
            256,
            "");
    try {
      String[] encrypt = cm.encrypt();
      // key
      assertNotEquals(null, encrypt[0]);
      // encrypted message
      assertNotEquals(null, encrypt[1]);
      // iv
      assertNotEquals(null, encrypt[2]);
      // hash
      assertNotEquals(null, encrypt[3]);
      // macKey
      assertEquals(null, encrypt[4]);
      // signature
      assertNotEquals(null, encrypt[5]);
      // signaturekey
      assertNotEquals(null, encrypt[6]);
      // salt
      assertEquals(null, encrypt[7]);
    } catch (Exception e) {
      fail();
      e.printStackTrace();
    }

  }

  @Test
  void decryptAesCbcWithoutPassword() {
    String expectedText = "000102030405060708090a0b0c0d0e0f";

    String[] keys = {"c12313e04f4ca357e0f0a423f486ac9b02b13c7ce6cd552a9bb04b004b1c02df", "51e865f8c52243693b22ae42a43eff70", "", "308203463082023906072a8648ce3804013082022c0282010100ae85afed38ee9fcbed9c61f1f1427794c5d0172a662d57d61911c40b33fa2ac213d07cfba672807ce11f050b687067f80270ce6cb3256950d7f92186b15bdbc6aa84551629cf28e8e7f5d104d6bd23101b61a6fa1d478b8bdb9663bf0983f3c225358e2b3f1e83fbeb40fe8d7a7c7b5bef1a3f06f5748a59b24ef7524bc0bd981aa2904ec99d74a1e4de52b12576bf60b25c3976ffe64a027757a7355af036f1e5f81e31844ca1d9068948a726012680a878024981d450ccf14a01ec21bc6093d3bfa0435dfab05dcb928c03f0e0865528c15a7defc95cdb570938fdda2287ac8ce2581fe29e4f9bbcd4be02408b83c0af8776e1bc8927e74d2f40ac4aadef9d022100aedb1cdb97bd26872e6094c17d5d695a1385cd06970a433ce3ab3acdac75e1390282010029c896c2cd9abcbc98f1aca699b4ba7cb4dd137efec311a0cdddd19710ed9ae7d99a331c79270e94b359be5439aeab9fdbb882b7bb94abb0372720b79f263cf3caa265d235d2d58e9b3b0feebc555d038cdb15ec01a50d81b20efdb40e7376a2dad3549a521a335a5ab11f7c22a6cb69785873f5f3c02e24b156b40da4f7583f420ca104f50ad3f95c74a85247d0b50144267f606cd65972c6a176491c38840c2f17fa7444ec61b6d320342b7ce225f376a1fb35920624504479cf7437375daa11395d27f9b3ed80025e41b4b98f84dde00281c476cd83cc8deb78c7aaae24c429386c8b9193171111e4081ce1810338d361b240bd2b7c65343135b09230f9e40382010500028201003e37ac722f576ffae94a2f3720da352761d89a3de1c7be7723084fe852db102fabebb1eea722e3be04952734b8883ee9bc74d42475698ccd834c83ed8f705afa247d68e59570111394c8e9858937806eb6fa34d1788f792e78952f0f6c20b87dd4b708a26c3db73442c6d71a7867929e763b0351a53b45879ca623e81c79e477a4696a94dcc7891b2dd7823f90ac7684d2f5c52d5056923ddf89eb95581b4ebdb4800b209d44e670c788db318346a6140c63fa9e9edb5fed318c1b239029f3c51e80049144944f049318a5324552a6906cead639f1eee4f9dd68d2a7b909c593f1e52fba35b0a0984d175a13b81efe57638fa1349f26e90f1b81521613d542ba"};
    CryptoManager cm = new CryptoManager(
            "3bd255608111f125fb9bb0cf69b5604e35bb1aaf988155eaad4533d1c33952bd",
            "AES",
            "CBC",
            "NoPadding",
            "SHA-256",
            "8afdc709ecfd1473f1db2550818e52e71beaf262fd223e9b182216d6340cb6a3",
            "3045022040c3a08193316c31d714e769d08103430d7401b4c25bfe7b3b430139d479b92c022100a4a7d5fe967975b6fca64cbaa75969fafddef6d4fbdbf3aa082edf1a774f33b3",
            keys,
            "",
            "");
    try {
      assertEquals(expectedText, cm.decrypt());
    } catch (Exception e) {
      fail();
      e.printStackTrace();
    }
  }

  @Test
  void decryptAesGcmScryptWithPassword() {
    String expectedText = "000102030405060708090a0b0c0d0e0f";

    String[] keys = {"", "b3dc5c01ce07eaadbefd567bb376a1a0", "", "308203463082023906072a8648ce3804013082022c02820101009be4dba62bed3ab236ebf8e5f1b97ee3aaf8116db72f82a5790a20863cfa7645f63bd8d3bfec62cc79a51d0421e4921e3b09b761fc13343c9fc4b37e807d3e175076adf0fbbf06d72c667ffdfd2ffcf488b585ee36c596352dc2ac36612c27144b7683a6a660a6cbe94b6cc450b580626417b4c8adbf526d7ea95198d1dcaa9f108084c8a9507293f027ed9c3105cef26520032c7edf643679150c8665ceb53c91ddd3cb4ea9418a7da87ea109a1021874e1901b1282f4e8ea3775cc4e74d417523dd76490415cdb02847f27d35979a204f8d9ccf7b5d325bfd3ea0a2ef868ad5ab5dcb583f9abf152e3a7601e5e3331b112cfc7607d1f3d0d1dd61f821fa1c7022100ae0a68bc5f3d1e1deb500072bba53cb6598bf3e988b74a964af2c99053b761c9028201001e0a202b63f93d63b89deda4fd203b20534d110bc26c654854794b473afc78052ebabfd3ba7c8d6061be80cf889569fa93799703f60f487947e22a628dc168f7304fdb46dc6f3714aa90825e492a6c81eb42dc843125b199e3385119faa4b764ff4aef7b22a7c793b6d2a714904135a5960b355728497dcd9354a12c438e56641fe0ff9bae738f400a08a7565b50e4f5dfab1b16ecca11c6ee966c4ee7b4ab102403b57789c97b514bddbeff05624fa9ac55e78379cd7ba20179a9bbf083725cf622010c47f3c5b98db9f189dd40356ad238d03277857ad60c3f747b079393d2c3989964d2732c7d52b44fa5763ab306b6cf116f905c0f2a41094f99fb3df9ca03820105000282010013ad663a12852c1de41618ad958f8162d80b1c3d3c0b0da26a04dd536bb680a18ee6f7b6f38c3539c8cddec4e16ce3ed56d41b9de78ff1e8ac754e27985fdbb1f15edebdec0dc9128e879a42ae43e7b79d0664d3759f0ea1624ba281110ece2d5172ed7734b460c827323c9e4cc0d2ffdf242c491303132181956a92f16a29e5e837c01d15880d7bc5118891f0edb44d06049e86b025374915b6cfc9d6078282b33cc12e5e47cbf0a0be546e1b3a8bfac223a1dd9e320ab0085888a94175e5a7abfd43c4a6a0ca291aaf403736aa5e4999ec8f26ea00acf1c4de6ed0c29e391724fecbcf0fa4207e2edd72c89a044e2f9d79ea5e3ff4570727c0077ebd4a0c47"};
    CryptoManager cm = new CryptoManager(
            "f4c6ddfbc9334c93b4df9447f5f5675a9156b7e5a9b68c1bab3f8829b1e0c78e62f9e3915da7f783da0a1caf08dca117",
            "AES256, GCM, SCrypt",
            "",
            "",
            "SHA-256",
            "6952698d7fc8621460edde7c996f7d2cf458caab62e6bf861947cf6d47c2dab4",
            "304402202b7a40a0948c66805c9998cbc15e016feffb9a065bb39a5af85099329beb0b770220176cd6ca516ec60b15b92c8118da95c421ec5030e8e1d88fb0bf2190e52c1cda",
            keys,
            "test123",
            "3732303961623731366237336561643933326632633565313234643664633434"
            );
    try {
      assertEquals(expectedText, cm.decrypt());
    } catch (Exception e) {
      fail();
      e.printStackTrace();
    }
  }

  @Test
  void decryptAesCcmScryptWithoutPassword() {
    String expectedText = "000102030405060708090a0b0c0d0e0f";

    String[] keys = {"2c87bb1c1918b6966a61bb0ea31a2c9e0f31f50c86063541c310393bbeca5300", "64ab39ef68f8fe43998d49c62f744de4", "", "308203483082023a06072a8648ce3804013082022d0282010100b27585beb77bacd8ed7d385f8c7ab20161c6ce22b07d6412020dce8edb960daeb81e0dd27f4d17c5644cf98b8f14dabe3af3d9725b310357f13157209d4eb2af4f5e305a6036ac5176a9fb2ff5ec6e4af8459d7b683f0b7eae618bdc70180f5f0056b48bbb1b5d0b6abcae0465835e9b2385b1144b0320a6f0ded7d7eca9f59f3c8aaae79ed42522b375be1894155b0214ad09a2994b2e9a37751517976df68d69d25dd220773ea9d4b4fbefc042525a6f00fc04af474ace27c90f1dafefd057b6a4272cac9d620efec4b8ac46184ca2d469575c9ee0485c9d2634367f9237a4f0ea49196941590a600cafa67924ecbccc99256fecb2868a734be0bba96fb7d3022100d4a8a768811532a24ca85364aa6a0db8e7a9ac1241de962c2fcceeb94273a0070282010100906528558729c71d46d8d76ed64c445a6553c10d303a05f21a24eefedeca83f811c72ea6e4ef8e7bc986f162b0b3ca0e4c1997965e081288cbd6ded6dffa11a246a60495401728598a516819afa713697b996193fa41e8bf4afc456b694d628ea38ac37d6aae1ac38fcae07c920dbcd4767c42aed6da3489bcb9896256afb8b0aa4da2a722949ea2c434356f5bd6955469abdcb83b5acfbbbd4fd0700065ba0dad7d22dcfd34062e53f6490fab86e5940d1ff63f76c0d70a016cc8aa4f8dd71a1440a869dd80776d066d3dfec09ce23b699ad5ce0eb9544e6c14b2f552765788e312858e3325b0ea1956939f15abc91746e2cd96907621d934d213b02108c95403820106000282010100a40e599a80b9b2d5472d8863a60f446d9bbde47eefd422f9def6afed15b15ce3488f778fbda43d3ceb3487c4b36e03b7652b742bccac4ce5e0e4b36a99b6ed81b59b83ab393974e45da8725f0de3865582a316a60885917ce44375341233b892ed2fb8c572ff7ff80db6898f37cda8ee21ffb5b827e29db62d202a8b9d36c47ce1071235462e13a04704c6388f5f04ba01209b456058ea616b1d7a3a81a27313fa6ea6cfed7a4b5a7f2f0f9d66c2204fd69a2c39e9e12a4d9bc844eb37cb4263730faf000aa82a55cbe27cb4521f58112d6e2c97db7a405d8dbb0d1d3650d79c7b881f2f1a9e7adfe14896462d0649385ac3f98007db320e9740896f265bf515"};
    CryptoManager cm = new CryptoManager(
            "e528d73b2a076085ed5a1c4258da8c0de89767e258c6ac9e1391db42e6beb1b7ce46fdcffcc92f40bf714d7b1f7d5fc2",
            "AES",
            "CCM",
            "NoPadding",
            "SHA-256",
            "120a610aa0106019dddf79e01e43a68543148effb8e8421c36da2547a44696c7",
            "30450221009d72916ec8ccff2528fd1f84e6a273bcc3d7d6e26f94fe84cf2384c25955ae7a022048752eea5414d0feead0a830c2e65732bec83e63a9d8dc341105370705bce82d",
            keys,
            "",
            ""
    );
    try {
      assertEquals(expectedText, cm.decrypt());
    } catch (Exception e) {
      fail();
      e.printStackTrace();
    }
  }

  @Test
  void decryptPBEWithSHA256And128BitAESCBCBC() {
    String expectedText = "000102030405060708090a0b0c0d0e0f";

    String[] keys = {"", null, "", "308203463082023906072a8648ce3804013082022c02820101008424c2d4f497134041b9110f706eb9f2be244b93cb634782f9ad46d656efb859a62f2a62c5d31b65211442be773e6e1c8a61e7ff2ac2344826aebd040b883785544e8479544470334d5a6b3f322acac5b404a8e76ab120ebcf1d21845decdc82012d7e2ab090a200b114b8221c021951aebb4bc28bde46d2cb82ea672fe65780693dabd571f4f0110876a56e984a4d578d3e29d87d50fcf7c013b9d65b61b7f9e30241664b37cda3194f5496adfe16fd4f474fbffbaccd4c6ba85534e4ebb270f83e727bea40a440089ea2f7ef4880313261ade92286cc93b8db685183ede12a7dcbc13a95450a2aef7a29feb6466f722723fc525b561fc2c12706bdd9d9c727022100b70dbeb30da5b2c57a970b22cfbfe4b1f858a50caa268d1cf647391158a227ef028201005dce5732a286c585c8025e6455fb36b2b2c9e3aa1367085807d099e9f98f3233a246a6c5c5cb9611717250cce0544532050d2740d0cff0f20c2318f639bd6cad267f748428de78521beb830e250aad19e8786762d620ae9c7c4f68d083a602678cab5a8f8cb485311b87d6d3ccf700fd1ae43cef3bfe5345fe70df384ac2385770753cbc79fc7baf507a19fd916e2340ada19d4f5d7f287283ce5b05ac738ca80afa19e97b33e277ae8ceddca18191a010ace3cd8e3de07ed719921595a193eed899d5c5b250f2cfd2d612d93bf8db61c314076bbc02857fb36be0d62288b4d0eb5d2bcd19c2005d2980e2d0d711eed71b187c95d2dbeb4166dda10942cdc9d6038201050002820100470f2b82d3c5856385684bfe0de5593bd52ef5f45935c734dbd70cc426e26a92c11b247353d2e0cd1ed944d3f16d3b54b0be28af869730ef9bd7de4e970b76e1e0a2bd4575839038dc9d7044ffc56876e9bd536bc85ec2fe53801ab78dc46d784b17a6a2e7bad70d7bb61b0ab3d250c97128a7ce4107e336a876752b67f91a11ac8f89329e141832ef718b611b0841db0494d83dd8405e4ad4410be608e263150132ac16ecdf1728696d03faff493008e31cb7693d6a42b7ecc18e25923b9fe882e1a38ead2b30f4b3a1bae0be0224a842a34a8abc1260e31a0e543972df405c86e69acabe4b5e3dce33ba3f58a6a13c0e27815390c61622769fa3940c456637"};
    CryptoManager cm = new CryptoManager(
            "603f612aded675a50a2543c987143d3c89d09ef1cd7b4b936c02122cb7749da4130281856dbf6ccdcf832db7692f9627",
            "PBEWithSHA256And128BitAES-CBC-BC",
            "",
            "",
            "SHA-256",
            "5d93f51e9ece5678fe499365336023213222efb916b263d6e9e7c4dacceef0df",
            "304402207aaa12681a13d7f8e9fc3bc8479f3b5228e043b697f2ec54c8324dd2f2f8073802203fece19da6bae3b9bb30b2ec4933cde1d925fabd9bcae9593866c0f796490f7e",
            keys,
            "teeeeeeeeeeeeeeeeeeeeeeeeeeest",
            "3465316465366339313634663434386164323235353332653430616437633330");
    try {
      assertEquals(expectedText, cm.decrypt());
    } catch (Exception e) {
      fail();
      e.printStackTrace();
    }
  }

  @Test
  void decryptPBEWithSHAAnd40BitRC4() {
    String expectedText = "000102030405060708090a0b0c0d0e0f";

    String[] keys = {"", "34534ad0d5de6f01c0eee7421b507039", null, "308203463082023906072a8648ce3804013082022c0282010100820ddd7bf37ee0ec03cfe5524c4dcec8dc09349992d7e6da90e12a0f51cc0634a0534029837823987b07e5ee20bcbca7ddf047338800a25b22015b13abf86f70ee69d0b1597f369d45e10acf02ef022f27eaeb91204a13bd810fe96ba5e1b099527f027814c5035e4cdecbd00e69fe8f1b412979cbd7187f66003f7f2ec88c734b17e50456769c6a1eb7d3d04d45e2adf40353ffa6bf2d2133dc7b95cd9e013781ec2aa6a1dc81347e179cf1e06825115773300ee80c4f3cc2214ab7b9a0223e7b48390ca9a23586fa1ef523e0e6c1532ed8291b33d653952db5cb20e0352db427d7acb01d43fad3e96f1bb528a649d7dffc5a8cf581b5ba8561458f4d1676e9022100ce31c0aadbdffa776462764b2cbde63201cfce4d1d7a61694593202aadaadead0282010048a3df9895d93b344b2d2f713971ba93580f5ab03c7674a7c41796c6593391e228452071ec698203dcdd437d829340031dcdd11e46935b2534e2db23467082d80a0bc4c02b2c5ea93688f92f24fb7c2b76e18b88fd0ae43946a3166a1034c9c0a91aa447778c0007b1fb6ab99f79ae0d770d816c8fa7e4f17ea9a4ae7329c4cef6f63ee713a1ea0803146b3b969ee2976a4d23e6ef29030124b7d9bdd776981203714fe9243d630ad908cab12fece963bdc43bb839716ac9ea2ef6d3979e643a0eb5e6b67f83fed65f9f671e62217e4f0aa531ae3672dcd836100e7caecd2d984c4a6b9b5be35ce46a26e46ca3315f9170520046d20e39b8d614a51f15c633de038201050002820100782237141856c6b56bb6c1b83be098092f9440c2fc1fa901e8af81edf3386d1c41d8a1e4ae698b88c621df938c9bcad7e51eda175af6c9b6f1bd9c8418689d0b79c63e29abe4fee7036085fc8bf2b1bd0ac81a2e48da881d6ad691d249ba89f801007544c9587bd84a83720fdda55019bb769131fef04fb8ccb4b2f99e91b1056ff97a992febdf4e39c02d95ae0bd0807018464c7496c30f879c5e78a167d69e0b767a9d37d90b9293611332d90e272bcf350048c0afc86bbd6dfc572f7d1d611dd0c11bab32175809b0a0ceda90e95aa379841e4521175dfcd4c0ced3fd27d58eab1b92a2dc8e6b4c44b034087a40f8c601b10d05942d89d76c73ae4a546ba2"};
    CryptoManager cm = new CryptoManager(
            "3f35bbab0f8b8a20fa73efac93ad6a493a89660c7527c7014b8c8a87391a4b3a",
            "PBEWithSHAAnd40BitRC4",
            "",
            "",
            "SHA-256",
            "1848e0148bed9a6e19e3d828c4e3347da7881960f306762729e423ea731de2dc",
            "3046022100855221d645df3d62d1a2e6739ab47d8d9e9dd72a2acef4c9669580f35edaec29022100c7124d882a63ebf00845473d8dcba0e79c83f23f68ab393f5fe154db6d7d84e0",
            keys,
            "testing it",
            "6539396562646234336565626131323038653831366461323866393935363238");
    try {
      assertEquals(expectedText, cm.decrypt());
    } catch (Exception e) {
      e.printStackTrace();
      fail();
    }
  }

  @Test
  void decryptAesCbcWithoutPasswordWithAESCMAC() {
    String expectedText = "000102030405060708090a0b0c0d0e0f";

    String[] keys = {"896034f5635c062b342268a98bbf143446564ff085cd9a2b710e68be5d4ff54b", "16452b510412fbfb46c8cd48611a7ec2", "805e9215553432a3c9f7bf528dfa32be08b740b5034fe624e7169cfbd3396b77", "308203473082023906072a8648ce3804013082022c0282010100c32040232c542a6e2719a3a27877eb15bf2f791645a5e4a658d2ec9871f7b05fee0df48f37181f369c521be3f3448de95ef6a1c3fe73f86875df3d1a67623f16794ea44950a063f3771648d2274b60a4a770be8306e2d8bc43b3f062389dd6ecc36b58218a85eb2be51635490811a05e9d2c576e3f7a59a3bd1d9d9e053c075071c69c461cd0c595243f6e252785df8a84bdeea89540e2ab5047912926f0aebd49f05b2ae417a1353dc35bcf726054bb69838ead3386610514e912c7d0c3c7a7ea1f624f06d371f9a4b9ea218a3acc4ee4686380bdb47cf5673350e90b3d4204eaaa78650a5bc80a16f1c09c897c8dacafee4ca779e56efdfbb001a1d8f1dda9022100faf94bc34053223db8bd5a626b5dc52694ad7ad70fd0efe8eb008766652a339f0282010052b30ca86066e4956c55005a2d1a2a17e74529079241133ba23afe56cce8a19d983a337b69b8042d4d749cae41dbcddfd535f8a437dba119c0ffabe2844af1379a73d776de8aeca044f9a9b5243f63053d67b03ae8418505dd47843d12aa6a9072af8c855a8d065d2b762733db70dd38df2e56803d0d8e7e05c3115b9c5475bf22e4f37773176ee54e7ec62e79b6e98f63b7a452a438393663fbcc48929306a3b0055728769f6972d39f69ba2817de4d9747164da913a3273e75b07a7b8b65116d28681bb7dbd1a0e8bd5c5c62ee650970a2b91fc4ee5c95157a199fe6a8c323ab403b621f07964de9d437eda207679eb3f848ed40e967f564e17bb517d2de0203820106000282010100a04def5ac56066de8f28b5cc2b5d14ecb0f1da17c7435a8086ff2fc62547c2774034fb1f428fb9d0dba826a3763186e1fc26155949afa129fc651515a261ebe1dc126b5bb411d13c033261602072ae50ca71118b7c9e7671bbb0f99e68a4dcace41a7d7183022742bcf36465c21a125e9ea4fb4d01b7c0b2c7c40e12028ab54063c607531e4bd9d31594bb769edd51a298ad84de226459a5f42b23fb06e01d0151d16018121f868dc4ff8b339eb3043893f1365864881254801f50a72d2914779152b43b3cbf8bbcfe80d70a97c4c7292df032fa94ae0aaa07a70235089d09dcb08c70d6b79bea7fd33a15d4b3c6da5a40feedda3789324d6759f22599e3a562"};
    CryptoManager cm = new CryptoManager(
            "23ab8e565bbb25062c2172d1372ee6a6ab95a8fe4777f04e24b74f067d06701f16ed824d9157da606dd55c82c6a58d15",
            "AES",
            "CBC",
            "PKCS5Padding",
            "AESCMAC",
            "d21a8261321f901c8e3d9ab8eecb6b11",
            "304502204eb8c73a35a4a8caf70d45fe4f2acde191e1a2857a5048751c77b5a8ce3510c7022100b5cd380ccaca62f533cc2f6bf956f76869cf9956671c6ef2100b115e06d68685",
            keys,
            "",
            "");
    try {
      assertEquals(expectedText, cm.decrypt());
    } catch (Exception e) {
      fail();
      e.printStackTrace();
    }
  }

  @Test
  void decryptAesCbcWithoutPasswordWithHMAC() {
    String expectedText = "000102030405060708090a0b0c0d0e";

    String[] keys = {"e347d1bd24096cb253cb48a0e93bd2b43168c7e187d18bc155ca721e9eacece2", "497f06b1fd718e39d0e88c991c660083", "8b752917115cdf06ca5484ab73116e0bc4251e0c59542c6502e1b30b9a72b759", "308203463082023906072a8648ce3804013082022c028201010082181652166e9d2e577281769182581d586f4cc86047939c916ebf8e285bacbb0df4d30f28c7e207bdc698193b413f915186bba9b28cb1866d88f2c11b251644dbbcc1d5a919b25e90f88db6ca388b85d7dd3ea4fb4babeae3298f8b687965dadc49d50112c8049a994cf92ee3e19240a8862327af745176f444ecd470e9146ce2b796f10c5164dc2f86221b696995bc13ff69999018616325ce7aaeb8bfa8dba77329a2c215b2949a68da925f97cb349d28529542dd87352337b3ae3ad163ecaa3601d5cf53670a37f90ca6c8b0d1e217893e3d0312f7bee133e52d5d32afafb1770f3869cdef21d5e4f5bf5d9d50d6526a0136e01678cbfaf71e977f182347022100ebcd75aa871fc6033dfe6e40c632b8c3863166737e52bb3ed4c4ca83f14318dd028201002c9aa7ce6e1aba8b529e5a31cb531c911df961bfcd2059fb2a4e67aecbcdeb7daaa06e69dfac49716019bfb8666658e190d626031131e3ff53c955342e9fcef48b5132788b55345c05d85b054d08edec443d6224fd3f4e4b44dbf62ff1df9f62d35183d5f1ff2e1b04260628e44b5cf41acd42bf7b20473af04e874c10fa15ae25eb62d47fad43706866560c1ef88ea88ef2d13fa59fce4f5322224a89de4b13da87ee5ccfba31800b749e1472dd82d7b03c03d0bf01d2f374c581f3f0ef186032ea301aebdf46d1349307afe41dd0edafcc3244532070d54b0f5699b379b6cceafd1c352e28fcce78b5c294c961187fa7c921987c9f4f58dbff2caf43594369038201050002820100423d85fbec2ea0a1e312f26e0de9cc8b67390dd7baa5cc2956142a047de553b2195e194e287768001cf76f5f9a7af1cc19750065a344467b95022408d758666988deafb1ac5a4d277dc4bd335654b9e8bdd76c24eb9b2dc2b1b7b46789d2b2fb9597563b76188e6cfd2e7a3cff84b74b4f9c7da2721db9b0097a506e828e411086630b22888484e84639136f5922b136c6d10ce036eb2d33be384c064fb7618adb327ff79e902f66b51fe96ec4d7fe4c3f6a3474d36b0dc72b343455d6e7d247bf8de784c1a43a92b1924045f8e6a7bdfd4d3b64c5488c05a6f26e939960b5dded95540cc012b99c114061394f586d8e56a90c0e5437d03df813d822fbc60d15"};
    CryptoManager cm = new CryptoManager(
            "cc52b1bd70d5121d0ade3fe415f2ae8d3eefbb376f34bae3cf693f50aaae115f",
            "AES",
            "CBC",
            "PKCS5Padding",
            "HmacSHA256",
            "0d0f03f90afc535976ef8aa3e6feb0202533994f3d9d7f234466b1b241c91fe1",
            "3044022067f624701484c297290e41701bdf8b347d78b98ca7be4ce2b0dfe8be246de68a022010f592bc18fad96fbcbb8fe0f58fec908bab0edf2e81413e825c1bb41c57bead",
            keys,
            "",
            "");
    try {
      assertEquals(expectedText, cm.decrypt());
    } catch (Exception e) {
      fail();
      e.printStackTrace();
    }
  }

  @Test
  void decryptAesEcbWithoutPassword() {
    String expectedText = "000102030405060708090a0b0c0d0e0f";

    String[] keys = {"87a5ece9c41682ba13c77832e7859a2e7b30d573bc1e0a99de9371f42770999d", "", "", "308203463082023906072a8648ce3804013082022c0282010100da88746a172b2adf4bffdfd0e135fcfd2b7852dd3f71296221605394e93c343bd20822682e7cd312f6d306e0e7dbf5883551ca7eaa7125b55fa6bf85e24544a47aa4472c8f503b8bf24a58d46940482bf1f8983b02b502d270a8af9a011972703a659321b91ff69554c757f92aed152bd4ef51419809d5b78f110d2440b9635a443eaa5570fa6720cea69688fd612c9863d3c57d6a87952e15711d61e927e272fea78c85fda54d6306d743e4555c836f73f46ca41acf6618e67359d56545ea2b6336f721bbec0c4f0232ca326dedc476a2d28d7537453188d4ec8362717644ca3db5a5963cfcb88338ed92acbbfc7db04771d7fd443ac3338bfd67ce357beadf0221008e2d2e0d20de67db4cc4efd1bcfb3d956fa8c7a8fda30451eba8ab7dd6cf86ed02820100306b1379bd264e58f1e63f7b7a0defec7c2a5e57c843a56cfcbafb17adff2b537438c8aedeede4828b717457d9132fba903f50b0e25dcb3a26a35bdf9323b2085a56d41cf189aae71e0bb0d891f2bbbf743b248cfc4569cf40458f6ef7fa7f0e2d367d6476167e58c1eacdd8a12847b32016eafb3f5b0253fa134c84b1566616f4b51cbd33dc03c97ba62f8f8c381300dd4a0cb97e04337d0b79b4044f8062181f28edbd1737e2dd322994b1e6e92336a3c1c0f2b998b86a28dc30fc3dc47320fe6bfaffec8ec7dd1cd984463791278a277ecb86cebfbb8bfb7a1370d77aa204d45ca32c8928f0c827223beb6d17d2439ee6298d418dc2558ec234c9ee1026f4038201050002820100522cf52a38473687f047d766e2b6fc81c3b0a4ea706a480949abb3df77104ff10ab08076d890242883ebe37366a9f80563162029d70c2ef53b86db3b8b0c15f41f454b2926f1458537336262007eb61e73cd32fec0aa5cc3b139f6f76bec4dd49143b4181568e1857533505f183a0bd1ef1769559a05c3107e0f57b4244ab77bc761bd76e61c255439fd2e7272552ba940611ba9da8ecefd72a18d39f7c83f002eb2c79781a537f21d73930109bfa072486c7d881b9e58ef22626c9c2213ceb5b297c1a75e2baed31f700944d9fde5a7e2cd434053f5d5c34aba78fa7e7c3670d37ceb424cb1285101ac61c1d5efe13676e7e561f329a6c3e416b1e39da8b246"};
    CryptoManager cm = new CryptoManager(
            "f8b38a0cb4d637de92522063beda116ff9787362f9b1515b8f28d5aa0d9229073b8d6607cd4979a366a219cc2a623435",
            "AES",
            "ECB",
            "PKCS5Padding",
            "SHA-256",
            "a8aa9c504fc5af988603c68e7b965b6b3c6474552ababb2944d3ea026cbe1dd7",
            "30450221008bdcc9d7f9d7e73c5dbecccd216603f9c8df0a9d9d491c686ea2b339b92bca9f0220775674e7d609cf67a7e01ec44c668dbc957d60f389b20cba94dcebc4ea0a241d",
            keys,
            "",
            "");
    try {
      assertEquals(expectedText, cm.decrypt());
    } catch (Exception e) {
      fail();
      e.printStackTrace();
    }
  }

  @Test
  void verifyMacFail() {
    String[] keys = {"896034f5635c062b342268a98bbf143446564ff085cd9a2b710e68be5d4ff54b", "16452b510412fbfb46c8cd48611a7ec2", "805e9215553432a3c9f7bf528dfa32be08b740b5034fe624e7169cfbd3396b77", "308203473082023906072a8648ce3804013082022c0282010100c32040232c542a6e2719a3a27877eb15bf2f791645a5e4a658d2ec9871f7b05fee0df48f37181f369c521be3f3448de95ef6a1c3fe73f86875df3d1a67623f16794ea44950a063f3771648d2274b60a4a770be8306e2d8bc43b3f062389dd6ecc36b58218a85eb2be51635490811a05e9d2c576e3f7a59a3bd1d9d9e053c075071c69c461cd0c595243f6e252785df8a84bdeea89540e2ab5047912926f0aebd49f05b2ae417a1353dc35bcf726054bb69838ead3386610514e912c7d0c3c7a7ea1f624f06d371f9a4b9ea218a3acc4ee4686380bdb47cf5673350e90b3d4204eaaa78650a5bc80a16f1c09c897c8dacafee4ca779e56efdfbb001a1d8f1dda9022100faf94bc34053223db8bd5a626b5dc52694ad7ad70fd0efe8eb008766652a339f0282010052b30ca86066e4956c55005a2d1a2a17e74529079241133ba23afe56cce8a19d983a337b69b8042d4d749cae41dbcddfd535f8a437dba119c0ffabe2844af1379a73d776de8aeca044f9a9b5243f63053d67b03ae8418505dd47843d12aa6a9072af8c855a8d065d2b762733db70dd38df2e56803d0d8e7e05c3115b9c5475bf22e4f37773176ee54e7ec62e79b6e98f63b7a452a438393663fbcc48929306a3b0055728769f6972d39f69ba2817de4d9747164da913a3273e75b07a7b8b65116d28681bb7dbd1a0e8bd5c5c62ee650970a2b91fc4ee5c95157a199fe6a8c323ab403b621f07964de9d437eda207679eb3f848ed40e967f564e17bb517d2de0203820106000282010100a04def5ac56066de8f28b5cc2b5d14ecb0f1da17c7435a8086ff2fc62547c2774034fb1f428fb9d0dba826a3763186e1fc26155949afa129fc651515a261ebe1dc126b5bb411d13c033261602072ae50ca71118b7c9e7671bbb0f99e68a4dcace41a7d7183022742bcf36465c21a125e9ea4fb4d01b7c0b2c7c40e12028ab54063c607531e4bd9d31594bb769edd51a298ad84de226459a5f42b23fb06e01d0151d16018121f868dc4ff8b339eb3043893f1365864881254801f50a72d2914779152b43b3cbf8bbcfe80d70a97c4c7292df032fa94ae0aaa07a70235089d09dcb08c70d6b79bea7fd33a15d4b3c6da5a40feedda3789324d6759f22599e3a562"};
    CryptoManager cm = new CryptoManager(
            "23ab8e565bbb25062c2172d1372ee6a6ab95a8fe4777f04e24b74f067d06701f16ed824d9157da606dd55c82c6a58d15",
            "AES",
            "CBC",
            "PKCS5Padding",
            "AESCMAC",
            "d21a8262321f901c8e3d9ab8eecb6b11",
            "304502204eb8c73a35a4a8caf70d45fe4f2acde191e1a2857a5048751c77b5a8ce3510c7022100b5cd380ccaca62f533cc2f6bf956f76869cf9956671c6ef2100b115e06d68685",
            keys,
            "",
            "");
    try {
      cm.decrypt();
      fail();
    } catch (Exception e) {
      assertEquals("Mac not equal", e.getMessage());
    }
  }

  @Test
  void verifyHashFail() {
    String[] keys = {"87a5ece9c41682ba13c77832e7859a2e7b30d573bc1e0a99de9371f42770999d", "", "", "308203463082023906072a8648ce3804013082022c0282010100da88746a172b2adf4bffdfd0e135fcfd2b7852dd3f71296221605394e93c343bd20822682e7cd312f6d306e0e7dbf5883551ca7eaa7125b55fa6bf85e24544a47aa4472c8f503b8bf24a58d46940482bf1f8983b02b502d270a8af9a011972703a659321b91ff69554c757f92aed152bd4ef51419809d5b78f110d2440b9635a443eaa5570fa6720cea69688fd612c9863d3c57d6a87952e15711d61e927e272fea78c85fda54d6306d743e4555c836f73f46ca41acf6618e67359d56545ea2b6336f721bbec0c4f0232ca326dedc476a2d28d7537453188d4ec8362717644ca3db5a5963cfcb88338ed92acbbfc7db04771d7fd443ac3338bfd67ce357beadf0221008e2d2e0d20de67db4cc4efd1bcfb3d956fa8c7a8fda30451eba8ab7dd6cf86ed02820100306b1379bd264e58f1e63f7b7a0defec7c2a5e57c843a56cfcbafb17adff2b537438c8aedeede4828b717457d9132fba903f50b0e25dcb3a26a35bdf9323b2085a56d41cf189aae71e0bb0d891f2bbbf743b248cfc4569cf40458f6ef7fa7f0e2d367d6476167e58c1eacdd8a12847b32016eafb3f5b0253fa134c84b1566616f4b51cbd33dc03c97ba62f8f8c381300dd4a0cb97e04337d0b79b4044f8062181f28edbd1737e2dd322994b1e6e92336a3c1c0f2b998b86a28dc30fc3dc47320fe6bfaffec8ec7dd1cd984463791278a277ecb86cebfbb8bfb7a1370d77aa204d45ca32c8928f0c827223beb6d17d2439ee6298d418dc2558ec234c9ee1026f4038201050002820100522cf52a38473687f047d766e2b6fc81c3b0a4ea706a480949abb3df77104ff10ab08076d890242883ebe37366a9f80563162029d70c2ef53b86db3b8b0c15f41f454b2926f1458537336262007eb61e73cd32fec0aa5cc3b139f6f76bec4dd49143b4181568e1857533505f183a0bd1ef1769559a05c3107e0f57b4244ab77bc761bd76e61c255439fd2e7272552ba940611ba9da8ecefd72a18d39f7c83f002eb2c79781a537f21d73930109bfa072486c7d881b9e58ef22626c9c2213ceb5b297c1a75e2baed31f700944d9fde5a7e2cd434053f5d5c34aba78fa7e7c3670d37ceb424cb1285101ac61c1d5efe13676e7e561f329a6c3e416b1e39da8b246"};
    CryptoManager cm = new CryptoManager(
            "f8b38a0cb4d637de92522063beda116ff9787362f9b1515b8f28d5aa0d9229073b8d6607cd4979a366a219cc2a623435",
            "AES",
            "ECB",
            "PKCS5Padding",
            "SHA-256",
            "a8aa9c504f5af988603c68e7b965b6b3c6474552ababb2944d3ea026cbe1dd7",
            "30450221008bdcc9d7f9d7e73c5dbecccd216603f9c8df0a9d9d491c686ea2b339b92bca9f0220775674e7d609cf67a7e01ec44c668dbc957d60f389b20cba94dcebc4ea0a241d",
            keys,
            "",
            "");
    try {
      cm.decrypt();
    } catch (Exception e) {
      assertEquals("Hash not equal", e.getMessage());
    }
  }

  @Test
  void verifyDigitalSignatureFail() {
    String[] keys = {"87a5ece9c41682ba13c77832e7859a2e7b30d573bc1e0a99de9371f42770999d", "", "", "308203463082023906072a8648ce3804013082022c0282010100da88746a172b2adf4bffdfd0e135fcfd2b7852dd3f71296221605394e93c343bd20822682e7cd312f6d306e0e7dbf5883551ca7eaa7125b55fa6bf85e24544a47aa4472c8f503b8bf24a58d46940482bf1f8983b02b502d270a8af9a011972703a659321b91ff69554c757f92aed152bd4ef51419809d5b78f110d2440b9635a443eaa5570fa6720cea69688fd612c9863d3c57d6a87952e15711d61e927e272fea78c85fda54d6306d743e4555c836f73f46ca41acf6618e67359d56545ea2b6336f721bbec0c4f0232ca326dedc476a2d28d7537453188d4ec8362717644ca3db5a5963cfcb88338ed92acbbfc7db04771d7fd443ac3338bfd67ce357beadf0221008e2d2e0d20de67db4cc4efd1bcfb3d956fa8c7a8fda30451eba8ab7dd6cf86ed02820100306b1379bd264e58f1e63f7b7a0defec7c2a5e57c843a56cfcbafb17adff2b537438c8aedeede4828b717457d9132fba903f50b0e25dcb3a26a35bdf9323b2085a56d41cf189aae71e0bb0d891f2bbbf743b248cfc4569cf40458f6ef7fa7f0e2d367d6476167e58c1eacdd8a12847b32016eafb3f5b0253fa134c84b1566616f4b51cbd33dc03c97ba62f8f8c381300dd4a0cb97e04337d0b79b4044f8062181f28edbd1737e2dd322994b1e6e92336a3c1c0f2b998b86a28dc30fc3dc47320fe6bfaffec8ec7dd1cd984463791278a277ecb86cebfbb8bfb7a1370d77aa204d45ca32c8928f0c827223beb6d17d2439ee6298d418dc2558ec234c9ee1026f4038201050002820100522cf52a38473687f047d766e2b6fc81c3b0a4ea706a480949abb3df77104ff10ab08076d890242883ebe37366a9f80563162029d70c2ef53b86db3b8b0c15f41f454b2926f1458537336262007eb61e73cd32fec0aa5cc3b139f6f76bec4dd49143b4181568e1857533505f183a0bd1ef1769559a05c3107e0f57b4244ab77bc761bd76e61c255439fd2e7272552ba940611ba9da8ecefd72a18d39f7c83f002eb2c79781a537f21d73930109bfa072486c7d881b9e58ef22626c9c2213ceb5b297c1a75e2baed31f700944d9fde5a7e2cd434053f5d5c34aba78fa7e7c3670d37ceb424cb1285101ac61c1d5efe13676e7e561f329a6c3e416b1e39da8b246"};
    CryptoManager cm = new CryptoManager(
            "f8b38a0cb4d637de92522063beda116ff9787362f9b1515b8f28d5aa0d9229073b8d6607cd4979a366a219cc2a623435",
            "AES",
            "ECB",
            "PKCS5Padding",
            "SHA-256",
            "a8aa9c504fc5af988603c68e7b965b6b3c6474552ababb2944d3ea026cbe1dd7",
            "30450223008bdcc9d7f9d7e73c5dbecccd216603f9c8df0a9d9d491c686ea2b339b92bca9f0220775674e7d609cf67a7e01ec44c668dbc957d60f389b20cba94dcebc4ea0a241d",
            keys,
            "",
            "");
    try {
      cm.decrypt();
    } catch (Exception e) {
      assertEquals("error decoding signature bytes.", e.getMessage());
    }
  }

  @Test
  void decryptAesGcmWithoutPassword() {
    String expectedText = "000102030405060708090a0b0c0d0e0f";

    String[] keys = {"d0b2f750b904b708f89b962bc589ccf4d4e237d61f3418e91933257401bfd21a", "9e6ea5bc17496c608af09241205c709c", "", "308203473082023906072a8648ce3804013082022c0282010100b4815b7146afac9a13cf8a588bcfda3bf16ad248822b2b020a6e4b1ec0077515ea14a571f829ccef7818075ade54bc633e853e104c9502eed5370f2d60676ce943b25fce02536e3a0a6a822679bdfcbabd7c687cb5f2ec34b363668360eb342566d3f1127175e74cd617d0b7a6b89630a098268aafa7ee28b2c492501313a2b0a43a5b7a7b489605e7a8bba068b17ebdd029ba0ab701f9e369c4d86cccd0e44dd960037fd7c43d07bc4c3e4fee540b96c5a471937802dcf8ab5438787fb23688187090d0e6431d886268b0c2a3b84a93a0a88bfcc330f719a271164428cd919c5207c5b7714f78c09e0633a809cb553a42767329024c7e68c563bdc297027bc7022100b84ecc7b26106b19505f5434e33c30aa72af7b8985f89befd9bde77019943bd7028201005b6ab05c5057345b8900446fa9befaf4ca9b3fdedbedc53ee2f64c331f7e6dd1c9fe18b02c1d05d12ca997bce2127523d3d79b77567e9371c32fdae434d2a8b582bd930519bf4af83e8f3e58ef233dd2518622544279a5c3557c7f54b6da93e7a8485615d741dec7933ce067f45ec40c1312062fe3be08c99183b2624a007d55925c8b88b62505934436092040a7bb20d7eb501262b39fe91568bd57e6951d3bd7c2aa67c3e70020991424548b6b684c4194a9eaa2ab05030733b23beecb524d26604bb15437cab439e0ac5e8362e50e43660a2a73066ad386e4cc4156e13c795d95cd733f9f1dc74a55e5121b16ecc91c8eaf5935bc6509d3edc310a5d2b38403820106000282010100a67bafc96a321c69ba9da7230d6561b855f00e3500cabd926fcd64715ce5a6f6ce8b8bb2c00a6a18af094d5f91e2d8c5e14b0da5cbc31e3df0433599ff577a11f68fa881a5dc6758a9552d07722f55b0f69fbaf3629c214cbd8af8793d8cf07ef5f684fea44e8ec9732a758e150174944fa6b9380750ef0d11528868c8dcc4b939f549b4311ecbae9394e5cee2d215934fc94fe02774087391b427ec73358c425254227ef4074454577e4e5b69d102af402a705ac1630da8a06bc482a37c1353c1b98eb182d7544a3abc4f13f9fb25ff2ed1637b468bdd800187e8b97b5e45bb14562362ab26dcc339cd04e80b2f1b3c243535a0a124f30a657f2e4017513038"};
    CryptoManager cm = new CryptoManager(
            "0a74aed70a68b3667dfcd41fa07af2c906e763e5c016791f9dfb8207a9b00b7b4470e531255ecab0a69bce5e64b08b40",
            "AES",
            "GCM",
            "NoPadding",
            "SHA-256",
            "4b074f84d02edaae6a42a2a6a2a52750d3e5da435a908767f455ed00430cf9ef",
            "3044022072ec1a13b36775748314caa55c8949ecf70f42f059fcd3c7bbdb788fa7057554022021630f9045215cbf5f6d09367f27c77450fd2299c5bb48a026b94f0ad17aecb2",
            keys,
            "",
            "");
    try {
      assertEquals(expectedText, cm.decrypt());
    } catch (Exception e) {
      fail();
      e.printStackTrace();
    }
  }
}
