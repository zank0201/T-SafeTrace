const fs = require('fs');
function parsed_data() {
    let apiData = {location_data: []};

    let read = fs.readFileSync('2019_AUGUST.json');
    let read_dec = fs.readFileSync('2019_DECEMBER.json');
    let read_feb = fs.readFileSync('2019_FEBRUARY.json');
    let read_jan = fs.readFileSync('2019_JANUARY.json');
    // let data = JSON.parse(read);

    let array = [JSON.parse(read), JSON.parse(read_dec), JSON.parse(read_feb),
    JSON.parse(read_jan)];
    let count = 1;
    for (i of array) {


        i.timelineObjects.forEach(function (obj) {
            if (Object.keys(obj) == 'placeVisit') {
                let user = "User" + count;
                let lat = obj.placeVisit.location.latitudeE7 / 10000000
                let lng = obj.placeVisit.location.longitudeE7 / 10000000
                let startTime = Math.floor(new Date(obj.placeVisit.duration.startTimestamp).valueOf() / 1000);
                let endTime = Math.floor(new Date(obj.placeVisit.duration.endTimestamp).valueOf() / 1000);
                let randomBool = Math.random() > 0.1 ? false : true;

                let obj_data = {
                    "userId": user,
                    "data": {"lat": lat, "lng": lng, "startTS": startTime, "endTS": endTime, "testResult": randomBool}
                }

                // apiData.location_data.push({"lat": lat, "lng": lng, "startTS": startTime, "endTS": endTime, "testResult": randomBool});
                apiData.location_data.push(obj_data);
                // apiData.users.push({"userId": user});
                count++;

            }

        });

        fs.writeFileSync("data.json", JSON.stringify(apiData, null, 4));
    }

    return apiData;
    }
// let august = fs.readFileSync('data.json');
// let aug_data = JSON.parse(august);
//
// console.log(Object.keys(august).length)
// parsed_data();
let read_test = fs.readFileSync("../../../../test.json");
let data = JSON.parse(read_test);
let parsed_test = data.encrypted_test;
fs.writeFileSync("jmeter_data.json", JSON.stringify(parsed_test, null, 4));
