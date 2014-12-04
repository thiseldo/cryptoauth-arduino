#include <AtSha204.h>
#include <AtEcc108.h>

AtEcc108 sha = AtEcc108();

void setup() {
    // put your setup code here, to run once:
    Serial.begin(9600);
    sha.enableDebug(&Serial);


}

void loop() {
    if (0 == sha.getRandom()){
        Serial.println("Success");
        sha.rsp.dumpHex(&Serial);
    }
    else{
        Serial.println("Failue");
    }

    delay(1000);


}
