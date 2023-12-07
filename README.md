# JAIID_WEB
JAIID WEB - A Realtime [ Jovian Artificial Intelligence Impact Detector ]

JAIID WEB is a cutting-edge real-time Jovian impact detector designed to monitor the celestial giant, Jupiter, for the elusive phenomena of impact flashes. This sophisticated web-based platform leverages the power of artificial intelligence through advanced models to detect and analyze potential impact events on the gas giant. Developed with a passion for celestial observation and an eye on scientific discovery, JAIID WEB employs state-of-the-art AI models to scrutinize live data streams from backyard amateur telescopes pointed at Jupiter, by constantly monitoring the planet's surface for abrupt luminosity changes or distinct shape detection that may indicate celestial collisions. The platform serves as a testament to the synergy between astronomy and artificial intelligence, pushing the boundaries of what we can uncover in the vastness of our solar system.

In addition to its sophisticated impact detection capabilities, JAIID WEB empowers users by providing the flexibility to upload and utilize your own artificial intelligence (AI) models. This unique feature allows enthusiasts and researchers to contribute to the platform's evolving capabilities by incorporating personalized models tailored to their specific preferences or research objectives. Users can leverage their expertise in AI and machine learning to enhance the precision of impact event detection, fostering a collaborative environment where the collective intelligence of the community contributes to the ongoing refinement of JAIID WEB's capabilities. This user-centric approach not only expands the platform's adaptability but also encourages a diverse range of perspectives in the pursuit of unraveling the mysteries of celestial events on Jupiter.

If you want to create you own models you must build datasets with (Visual Object Tagging Tool). https://github.com/Microsoft/VoTT/releases

It should be acknowledged that the efficacy of JAIID WEB, in detecting impact flashes on Jupiter, may be influenced by varying atmospheric conditions and the quality of observational "seeing." These factors introduce the possibility of encountering false positives, where certain luminosity fluctuations may be erroneously identified as impact events. It is crucial to consider the dynamic nature of Earth's atmosphere and atmospheric turbulence, as they can impact the accuracy of the detection system. As a result, users should exercise discernment and interpret the results in light of prevailing atmospheric conditions, understanding that occasional false positives may arise due to uncontrollable environmental variables.

JAIID currently supports ZWO Cameras - Tested with ZWO ASI 290mc !!!


The mechanish for trainning JAIID AI models: https://github.com/ibsoft/JAIID/

Ioannis A. (Yannis) Bouhras [ ioannis.bouhras@gmail.com ] [ mycyberdevops@gmail.com ] - Project based on Ultralytics YOLO8 real-time object detection and image segmentation model !!!

INSTALLATION



1. Clone the repository [ git clone https://github.com/ibsoft/JAIID_WEB.git ]
2. Connect your camera !!! <-- IMPORTANT
3. [ cd JAIID_WEB ]
4. IF LINUX [ python3 -m venv venv ]
5. IF WINDOWS [ python -m venv venv ]
6. IF LINUX [ source venv/bin/activate ]
7. IF WINDOWS [ .\venv\Scripts\activate ]
8. IF LINUX [ pip install -r requirements-linux.txt ]
9. IF WINDOWS [ pip install requirements-windows.txt]
10. [ pip install ultralytics ]
11. [ flask run ]
12. Point your browser to http://localhost:5000/
13. Login

    Username: admin
    Password: !Astronomy7?

    Username: jaiid
    Password: !Astronomy7?

Happy hunting!! Enjoy!

License

JAIID embraces the GNU Affero General Public License v3.0 (AGPL-3.0) for its repositories, promoting openness, transparency, and collaborative enhancement in software development. This strong copyleft license ensures that all users and developers retain the freedom to use, modify, and share the software. It fosters community collaboration, ensuring that any improvements remain accessible to all.

Users and developers are encouraged to familiarize themselves with the terms of AGPL-3.0 to contribute effectively and ethically to the JAIID open-source community.
